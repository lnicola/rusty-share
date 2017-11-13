extern crate bytes;
extern crate bytesize;
extern crate chrono;
extern crate chrono_humanize;
extern crate futures;
extern crate futures_cpupool;
extern crate futures_fs;
extern crate hyper;
extern crate pretty_env_logger;
extern crate url;

use bytes::Bytes;
use bytesize::ByteSize;
use chrono::{DateTime, Local, TimeZone};
use chrono_humanize::HumanTime;
use futures::future;
use futures::{stream, Future, Sink, Stream};
use futures_cpupool::CpuPool;
use futures_fs::FsPool;
use hyper::{Get, Post, StatusCode};
use hyper::header::{ContentLength, Location};
use hyper::server::{Http, Request, Response, Service};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::fmt::Write;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use url::percent_encoding;

struct Server {
    pool: CpuPool,
    fs_pool: Arc<FsPool>,
}

impl Service for Server {
    type Request = Request;
    type Response = Response<Box<Stream<Item = Bytes, Error = Self::Error> + Send>>;
    type Error = hyper::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Request) -> Self::Future {
        type Body = Box<Stream<Item = Bytes, Error = hyper::Error> + Send>;

        let root = Path::new(".");
        let response = match (req.method(), req.path()) {
            (&Get, path_) => {
                let path_ = percent_encoding::percent_decode(path_.as_bytes())
                    .decode_utf8()
                    .unwrap()
                    .into_owned();
                let path = Path::new(&path_);
                let path = path.strip_prefix("/").unwrap();
                let path = root.join(path);
                let metadata = fs::metadata(&path);
                if metadata.is_err() {
                    let response = Response::new().with_status(StatusCode::InternalServerError);
                    Box::new(future::ok(response))
                } else {
                    let metadata = metadata.unwrap();
                    if metadata.is_dir() {
                        if !path_.ends_with('/') &&
                            fs::symlink_metadata(&path)
                                .unwrap()
                                .file_type()
                                .is_symlink()
                        {
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
            (&Post, _path) => {
                let (tx, rx) = futures::sync::mpsc::channel::<Bytes>(10);
                let r = self.pool.spawn_fn(|| tx.send(Bytes::from("hello"))).then(
                    |_| {
                        let response =
                            Response::new()
                                .with_status(StatusCode::Ok)
                                .with_body(Box::new(rx.map_err(|_| hyper::Error::Method)) as Body);
                        Box::new(future::ok(response))
                    },
                );
                return Box::new(r);
            }
            _ => {
                let response = Response::new().with_status(StatusCode::InternalServerError);
                Box::new(future::ok(response))
            }
        };

        Box::new(self.pool.spawn(response))
    }
}

fn main() {
    pretty_env_logger::init().unwrap();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3010);

    let server = Http::new()
        .bind(&addr, || {
            Ok(Server {
                pool: CpuPool::new_num_cpus(),
                fs_pool: Arc::new(FsPool::new(4)),
            })
        })
        .unwrap();
    println!(
        "Listening on http://{} with 1 thread.",
        server.local_addr().unwrap()
    );
    server.run().unwrap();
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
    use std::os::unix::ffi::OsStrExt;
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
