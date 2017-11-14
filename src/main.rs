extern crate bytes;
extern crate bytesize;
extern crate chrono;
extern crate chrono_humanize;
extern crate futures;
extern crate futures_cpupool;
extern crate futures_fs;
extern crate hyper;
extern crate pretty_env_logger;
extern crate tar;
extern crate tokio_core;
extern crate url;
extern crate walkdir;

use bytes::Bytes;
use bytesize::ByteSize;
use chrono_humanize::HumanTime;
use chrono::{DateTime, Local, TimeZone};
use futures_cpupool::CpuPool;
use futures_fs::FsPool;
use futures::{stream, Future, Sink, Stream};
use futures::future::{self, FutureResult};
use futures::sync::mpsc;
use hyper::{Get, Post, StatusCode};
use hyper::header::{Charset, ContentDisposition, ContentLength, ContentType, DispositionParam,
                    DispositionType, Location};
use hyper::mime::{Mime, TEXT_HTML_UTF_8};
use hyper::server::{Http, Request, Response, Service};
use std::error;
use std::ffi::OsString;
use std::fmt::Write;
use std::fs::{self, File};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::UNIX_EPOCH;
use tar::Builder;
use tokio_core::net::TcpListener;
use tokio_core::reactor::{Core, Handle};
use url::{form_urlencoded, percent_encoding};
use walkdir::{DirEntry, WalkDir};

struct Pipe {
    dest: futures::sink::Wait<futures::sync::mpsc::Sender<Bytes>>,
}

impl io::Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.dest.send(Bytes::from(buf)) {
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Interrupted, e)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.dest.flush() {
            Ok(_) => Ok(()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Interrupted, e)),
        }
    }
}

struct Archiver;

impl Archiver {
    fn write_entry<W>(
        &self,
        root: &Path,
        entry: &DirEntry,
        builder: &mut Builder<W>,
    ) -> std::result::Result<(), Box<error::Error>>
    where
        W: io::Write,
    {
        let relative_path = try!(entry.path().strip_prefix(&root));
        let metadata = try!(entry.metadata());
        if metadata.is_dir() {
            try!(builder.append_dir(&relative_path, &entry.path()));
        } else {
            let mut file = try!(File::open(&entry.path()));
            try!(builder.append_file(&relative_path, &mut file));
        }

        Ok(())
    }

    fn add_to_archive<P, Q, W>(
        &self,
        root: P,
        entry: Q,
        builder: &mut Builder<W>,
    ) -> std::io::Result<()>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
        W: io::Write,
    {
        let walkdir = WalkDir::new(root.as_ref().join(&entry));
        let entries = walkdir
            .into_iter()
            .filter_entry(|e| !Archiver::is_hidden(e));
        for e in entries {
            if let Ok(e) = e {
                if let Err(e) = self.write_entry(root.as_ref(), &e, builder) {
                    println!("{:?}", e);
                }
            } else {
                println!("{:?}", e);
            }
        }
        Ok(())
    }

    fn is_hidden(entry: &DirEntry) -> bool {
        entry
            .file_name()
            .to_str()
            .map_or(true, |s| s.starts_with('.'))
    }
}

struct Server {
    handle: Handle,
    fs_pool: FsPool,
    pool: CpuPool,
}

impl Service for Server {
    type Request = Request;
    type Response = Response<Box<Stream<Item = Bytes, Error = Self::Error> + Send>>;
    type Error = hyper::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Request) -> Self::Future {
        type Body = Box<Stream<Item = Bytes, Error = hyper::Error> + Send>;

        let root = Path::new(".");
        let path_ = percent_encoding::percent_decode(req.path().as_bytes())
            .decode_utf8()
            .unwrap()
            .into_owned();
        let path = Path::new(&path_);
        let path = path.strip_prefix("/").unwrap();
        let path = root.join(path);
        let response = match *req.method() {
            Get => {
                let metadata = fs::metadata(&path);
                if metadata.is_err() {
                    let response = Response::new().with_status(StatusCode::InternalServerError);
                    Box::new(future::ok(response))
                } else {
                    let metadata = metadata.unwrap();
                    if metadata.is_dir() {
                        if !path_.ends_with('/') {
                            let response = Response::new()
                                .with_status(StatusCode::Found)
                                .with_header(Location::new(path_.to_string() + "/"));
                            Box::new(future::ok(response))
                        } else {
                            let page = get_dir_index(&path).unwrap();
                            let bytes = Bytes::from(page);
                            let len = bytes.len() as u64;
                            let body = Box::new(stream::once(Ok(bytes))) as Body;
                            let response = Response::new()
                                .with_status(StatusCode::Ok)
                                .with_header(ContentType(TEXT_HTML_UTF_8))
                                .with_header(ContentLength(len))
                                .with_body(body);

                            Box::new(future::ok(response))
                        }
                    } else {
                        let body = Box::new(self.fs_pool.read(path).map_err(|e| e.into())) as Body;
                        let response = Response::new()
                            .with_status(StatusCode::Ok)
                            .with_header(ContentLength(metadata.len()))
                            .with_body(body);

                        Box::new(future::ok(response))
                    }
                }
            }
            Post => {
                let pool = self.pool.clone();
                let handle = self.handle.clone();
                let b = req.body().concat2().and_then(move |b| {
                    let (tx, rx) = mpsc::channel(10);

                    let f = pool.spawn_fn(move || -> FutureResult<_, ()> {
                        let pipe = Pipe { dest: tx.wait() };

                        let mut a = Builder::new(pipe);
                        let archiver = Archiver;

                        for (name, value) in form_urlencoded::parse(&b) {
                            if name == "selection[]" {
                                archiver
                                    .add_to_archive(&path, Path::new(value.as_ref()), &mut a)
                                    .unwrap();
                            }
                        }


                        future::ok(())
                    });
                    handle.spawn(f);

                    Ok(
                        Response::new()
                            .with_header(ContentDisposition {
                                disposition: DispositionType::Attachment,
                                parameters: vec![
                                    DispositionParam::Filename(
                                        Charset::Iso_8859_1,
                                        None,
                                        b"archive.tar".to_vec(),
                                    ),
                                ],
                            })
                            .with_header(ContentType("application/x-tar".parse::<Mime>().unwrap()))
                            .with_body(Box::new(rx.map_err(|_| hyper::Error::Incomplete)) as Body),
                    )
                });
                return Box::new(b);
            }
            _ => {
                let response = Response::new().with_status(StatusCode::MethodNotAllowed);
                Box::new(future::ok(response))
            }
        };

        Box::new(self.pool.spawn(response))
    }
}

fn main() {
    pretty_env_logger::init().unwrap();

    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3010);
    let listener = TcpListener::bind(&addr, &handle).unwrap();

    let fs_pool = FsPool::new(4);
    let cpu_pool = CpuPool::new_num_cpus();

    let server = listener.incoming().for_each(move |(sock, addr)| {
        let s = Server {
            handle: handle.clone(),
            fs_pool: fs_pool.clone(),
            pool: cpu_pool.clone(),
        };

        Http::new().bind_connection(&handle, sock, addr, s);

        Ok(())
    });
    core.run(server).unwrap();
}

#[derive(Debug)]
struct ShareEntry {
    name: OsString,
    is_dir: bool,
    size: u64,
    modified: DateTime<Local>,
}

impl ShareEntry {
    fn new(name: OsString, is_dir: bool, size: u64, modified: DateTime<Local>) -> ShareEntry {
        ShareEntry {
            name: name,
            is_dir: is_dir,
            size: size,
            modified: modified,
        }
    }
}

fn render_index(entries: &[ShareEntry]) -> String {
    let doc_header = r#"<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <script>
        document.addEventListener("DOMContentLoaded", function () {
            let rows = document.getElementsByTagName("tr");
            let playlist = [];
            for (let i = 2; i < rows.length; i++) {
                let anchor = rows[i].children[1].children[0];
                let entry = {
                    title: anchor.innerText,
                    href: anchor.href
                };
                if (entry.href.endsWith(".mp3") || entry.href.endsWith(".flac")) {
                    playlist.push(entry);
                }
            }

            if (playlist.length > 0) {
                playlist.sort(function (a, b) {
                    if (a.title < b.title) {
                        return -1;
                    } else if (a.title > b.title) {
                        return 1;
                    } else {
                        return 0;
                    }
                });

                let currentIndex = 0;
                let title = document.createElement("p");
                let titleText = document.createTextNode(playlist[0].title);
                title.appendChild(titleText);
                let audio = new Audio(playlist[0].href);
                audio.controls = true;
                audio.addEventListener("ended", function () {
                    if (++currentIndex < playlist.length) {
                        this.src = playlist[currentIndex].href;
                        titleText.nodeValue = playlist[currentIndex].title;
                        audio.play();
                    }
                });
                document.body.appendChild(title);
                document.body.appendChild(audio);
            }
        });
    </script>

    <style>
        body {
            padding: 20px;
            font-family: sans-serif;
        }
        .view {
            width: 100%;
            border-left: 1px solid #ededed;
            border-right: 1px solid #ededed;
        }
        table {
            border-collapse: collapse;
        }
        col.selected {
            width: 20px;
        }
        col.size {
            width: 100px;
            text-align: right;
        }
        col.date {
            width: 200px;
        }
        tr {
            border-bottom: 1px solid #ededed;
        }
        tr.header {
            background-color: #fafafa;
            border-top: 1px solid #ededed;
        }
        tr:hover {
            background-color: #f0f0f0;
        }
        th {
            font-weight: normal;
        }
        th,td {
            padding: 8px;
            text-align: left;
        }
        th:nth-child(3) {
            text-align: right;
        }
        th:nth-child(4) {
            text-align: right;
        }
        td:nth-child(3) {
            text-align: right;
        }
        td:nth-child(4) {
            text-align: right;
        }
    </style>
</head>
<body>
    <form method="POST">
        <table class="view">
            <colgroup>
                <col class="selected" />
                <col class="name" />
                <col class="size" />
                <col class="date" />
            </colgroup>
            <tr class="header">
                <th></th>
                <th>Name</th>
                <th>Size</th>
                <th>Last modified</th>
            </tr>
            <tr>
                <td></td>
                <td><a href="..">../</a></td>
                <td></td>
                <td></td>
            </tr>
            "#;
    let doc_footer = r#"        </table>
        <input type="submit" value="Download" />
    </form>
</body>
</html>"#;
    let mut res = String::from(doc_header);

    for entry in entries.iter() {
        let modified = HumanTime::from(entry.modified);
        let link = percent_encoding::percent_encode(
            entry.name.as_bytes(),
            percent_encoding::DEFAULT_ENCODE_SET,
        );
        if entry.is_dir {
            write!(
                res,
                r#"<tr><td><input name="selection[]" value="{}" type="checkbox"></td><td><a href="{}">{}</a></td><td></td><td>{}</td></tr>"#,
                link,
                link,
                entry.name.to_string_lossy().into_owned(),
                modified
            ).unwrap();
        } else {
            write!(
                res,
                r#"<tr><td><input name="selection[]" value="{}" type="checkbox"></td><td><a href="{}">{}</a></td><td>{}</td><td>{}</td></tr>"#,
                link,
                link,
                entry.name.to_string_lossy().into_owned(),
                ByteSize::b(entry.size as usize).to_string(false),
                modified
            ).unwrap();
        }
    }
    res.push_str(doc_footer);
    res
}

fn get_dir_index(path: &Path) -> io::Result<String> {
    let mut entries = Vec::new();
    for file in fs::read_dir(&path)? {
        let entry = file?;
        let metadata = entry.metadata()?;
        let mut file = entry.file_name();
        if !(file.as_ref() as &Path).starts_with(".") {
            let modified = metadata.modified()?;
            let duration = modified.duration_since(UNIX_EPOCH).unwrap();
            let datetime = Local.timestamp(duration.as_secs() as i64, duration.subsec_nanos());
            if metadata.is_dir() {
                file.push("/");
            }
            entries.push(ShareEntry::new(
                file,
                metadata.is_dir(),
                metadata.len(),
                datetime,
            ));
        }
    }

    entries.sort_by_key(|e| (!e.is_dir, e.modified));

    Ok(render_index(&entries))
}
