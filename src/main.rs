extern crate bytes;
extern crate bytesize;
extern crate chrono;
extern crate chrono_humanize;
extern crate failure;
extern crate futures;
extern crate futures_cpupool;
extern crate futures_fs;
#[macro_use]
extern crate horrorshow;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate pretty_env_logger;
extern crate rayon;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate tar;
extern crate tokio_core;
extern crate url;
extern crate walkdir;

use bytes::Bytes;
use bytesize::ByteSize;
use chrono_humanize::HumanTime;
use chrono::{DateTime, Local};
use failure::{Error, ResultExt};
use futures_cpupool::CpuPool;
use futures_fs::FsPool;
use futures::{future, stream, Future, Sink, Stream};
use futures::sink::Wait;
use futures::sync::mpsc::{self, Sender};
use horrorshow::prelude::*;
use horrorshow::helper::doctype;
use hyper::{Get, Post, StatusCode};
use hyper::header::{Charset, ContentDisposition, ContentLength, ContentType, DispositionParam,
                    DispositionType, Location};
use hyper::mime::{Mime, TEXT_HTML_UTF_8};
use hyper::server::{self, Http, Request, Response, Service};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::slice::ParallelSliceMut;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use structopt::StructOpt;
use tar::Builder;
use tokio_core::reactor::{Core, Handle};
use url::{form_urlencoded, percent_encoding};
use walkdir::WalkDir;

struct Pipe {
    dest: Wait<Sender<Bytes>>,
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.dest.send(Bytes::from(buf)) {
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(io::Error::new(ErrorKind::Interrupted, e)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.dest.flush() {
            Ok(_) => Ok(()),
            Err(e) => Err(io::Error::new(ErrorKind::Interrupted, e)),
        }
    }
}

struct Archiver<W: Write> {
    builder: Builder<W>,
}

impl<W: Write> Archiver<W> {
    fn new(builder: Builder<W>) -> Self {
        Self { builder }
    }
}

impl<W: Write> Archiver<W> {
    fn write_entry(&mut self, root: &Path, entry: &walkdir::DirEntry) -> Result<(), Error>
    where
        W: Write,
    {
        let metadata = entry.metadata().with_context(|_| {
            format!("Unable to read metadata for {}", entry.path().display())
        })?;
        let relative_path = entry.path().strip_prefix(&root).with_context(|_| {
            format!(
                "Unable to make path {} relative from {}",
                entry.path().display(),
                root.display()
            )
        })?;
        if metadata.is_dir() {
            self.builder
                .append_dir(&relative_path, entry.path())
                .with_context(|_| {
                    format!("Unable to add {} to archive", entry.path().display())
                })?;
        } else {
            let mut file = File::open(&entry.path())
                .with_context(|_| format!("Unable to open {}", entry.path().display()))?;
            self.builder
                .append_file(&relative_path, &mut file)
                .with_context(|_| {
                    format!("Unable to add {} to archive", entry.path().display())
                })?;
        }

        Ok(())
    }

    fn add_to_archive<P, Q>(&mut self, root: P, entry: Q)
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
        W: Write,
    {
        let walkdir = WalkDir::new(root.as_ref().join(&entry));
        let entries = walkdir.into_iter().filter_entry(|e| !Self::is_hidden(e));
        for e in entries {
            match e {
                Ok(e) => if let Err(e) = self.write_entry(root.as_ref(), &e) {
                    error!("{}", e);
                },
                Err(e) => error!("{}", e),
            }
        }
    }

    fn is_hidden(entry: &walkdir::DirEntry) -> bool {
        entry
            .file_name()
            .to_str()
            .map_or(true, |s| s != "./." && s.starts_with('.'))
    }
}

#[derive(Clone, Debug, StructOpt)]
struct Options {
    #[structopt(short = "r", long = "root", help = "Root path", default_value = ".",
                parse(from_os_str))]
    root: PathBuf,
}

struct RustyShare {
    options: Options,
    handle: Handle,
    fs_pool: FsPool,
    pool: CpuPool,
}

impl RustyShare {
    fn handle_get(&self, path: PathBuf, path_: &str) -> Result<<Self as Service>::Future, Error> {
        type Body = Box<Stream<Item = Bytes, Error = hyper::Error> + Send>;
        let metadata = fs::metadata(&path)
            .with_context(|_| format!("Unable to read metadata of {}", path.display()))?;
        if metadata.is_dir() {
            if !path_.ends_with('/') {
                let response = Response::new()
                    .with_status(StatusCode::Found)
                    .with_header(Location::new(path_.to_string() + "/"));
                Ok(Box::new(future::ok(response)))
            } else {
                let f = self.pool.spawn_fn(move || {
                    let enumerate_start = Instant::now();
                    let entries = get_dir_index(&path);
                    let enumerate_time = Instant::now() - enumerate_start;
                    let response = match entries {
                        Ok(entries) => {
                            let render_start = Instant::now();
                            let rendered = render_index(entries);
                            let render_time = Instant::now() - render_start;
                            let bytes = Bytes::from(rendered);
                            info!(
                                "enumerate: {} ms, render: {} ms",
                                enumerate_time.to_millis(),
                                render_time.to_millis()
                            );
                            let len = bytes.len() as u64;
                            let body = Box::new(stream::once(Ok(bytes))) as Body;
                            Response::new()
                                .with_status(StatusCode::Ok)
                                .with_header(ContentType(TEXT_HTML_UTF_8))
                                .with_header(ContentLength(len))
                                .with_body(body)
                        }
                        Err(e) => {
                            error!("{}", e);
                            Response::new().with_status(StatusCode::InternalServerError)
                        }
                    };

                    future::ok(response)
                });
                Ok(Box::new(f))
            }
        } else {
            let body = Box::new(self.fs_pool.read(path).map_err(|e| e.into())) as Body;
            let response = Response::new()
                .with_status(StatusCode::Ok)
                .with_header(ContentLength(metadata.len()))
                .with_body(body);

            Ok(Box::new(future::ok(response)))
        }
    }
}

impl Service for RustyShare {
    type Request = Request;
    type Response = Response<Box<Stream<Item = Bytes, Error = Self::Error> + Send>>;
    type Error = hyper::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Request) -> Self::Future {
        type Body = Box<Stream<Item = Bytes, Error = hyper::Error> + Send>;

        let root = self.options.root.as_path();
        let path_ = percent_encoding::percent_decode(req.path().as_bytes())
            .decode_utf8()
            .unwrap()
            .into_owned();
        let path = root.join(Path::new(&path_).strip_prefix("/").unwrap());
        match *req.method() {
            Get => match self.handle_get(path, &path_) {
                Ok(response) => response,
                Err(e) => {
                    error!("{}", e);
                    let response = Response::new().with_status(StatusCode::InternalServerError);
                    Box::new(future::ok(response))
                }
            },
            Post => {
                let pool = self.pool.clone();
                let handle = self.handle.clone();
                let b = req.body().concat2().and_then(move |b| {
                    let mut files = Vec::new();
                    for (name, value) in form_urlencoded::parse(&b) {
                        if name == "s" {
                            let value = percent_encoding::percent_decode(value.as_bytes())
                                .decode_utf8()
                                .unwrap()
                                .into_owned();
                            files.push(value)
                        } else {
                            let response = Response::new().with_status(StatusCode::BadRequest);
                            return Ok(response);
                        }
                    }

                    let archive_name = match files.len() {
                        0 => {
                            files.push(String::from("."));
                            (path_.clone() + ".tar").as_bytes().to_vec()
                        }
                        1 => (files[0].clone() + ".tar").as_bytes().to_vec(),
                        _ => b"archive.tar".to_vec(),
                    };

                    let (tx, rx) = mpsc::channel(10);
                    let f = pool.spawn_fn(move || {
                        let pipe = Pipe { dest: tx.wait() };

                        let mut archiver = Archiver::new(Builder::new(pipe));
                        for file in files {
                            archiver.add_to_archive(&path, &file);
                        }

                        future::ok::<_, ()>(())
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
                                        archive_name,
                                    ),
                                ],
                            })
                            .with_header(ContentType("application/x-tar".parse::<Mime>().unwrap()))
                            .with_body(Box::new(rx.map_err(|_| hyper::Error::Incomplete)) as Body),
                    )
                });
                Box::new(b)
            }
            _ => {
                let response = Response::new().with_status(StatusCode::MethodNotAllowed);
                Box::new(future::ok(response))
            }
        }
    }
}

fn run() -> Result<(), Error> {
    let options = Options::from_args();

    let mut core = Core::new().context("Unable to create the Core")?;
    let handle = core.handle();

    let server = RustyShare {
        options: options,
        handle: handle.clone(),
        fs_pool: FsPool::default(),
        pool: CpuPool::new_num_cpus(),
    };

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3010);
    let server = Http::new()
        .serve_addr_handle(&addr, &handle, server::const_service(server))
        .context("Unable to start server")?
        .for_each(move |conn| {
            handle.spawn(conn.map(|_| ()).map_err(|e| error!("{}", e)));
            Ok(())
        });

    core.run(server).context("Unable to run server")?;
    Ok(())
}

fn main() {
    pretty_env_logger::init().expect("Unable to initialize logger");

    if let Err(e) = run() {
        error!("{}", e);
    }
}

#[derive(Debug)]
struct ShareEntry {
    name: OsString,
    is_dir: bool,
    size: u64,
    date: DateTime<Local>,
}

fn render_index(entries: Vec<ShareEntry>) -> String {
    (html! {
        : doctype::HTML;
        html {
            head {
                script { : Raw(include_str!("../assets/player.js")) }
                style { : Raw(include_str!("../assets/style.css")); }
            }
            body {
                form(method="POST") {
                    table(class="view") {
                        colgroup {
                            col(class="selected");
                            col(class="name");
                            col(class="size");
                            col(class="date");
                        }
                        tr(class="header") {
                            th;
                            th { : Raw("Name") }
                            th { : Raw("Size") }
                            th { : Raw("Last modified") }
                        }
                        tr { td; td { a(href=Raw("..")) { : Raw("..") } } td; td; }
                        @ for ShareEntry { mut name, is_dir, size, date } in entries {
                            |tmpl| {
                                let mut display_name = name;
                                if is_dir {
                                    display_name.push("/");
                                }
                                let link = percent_encoding::percent_encode(
                                    display_name.as_bytes(),
                                    percent_encoding::DEFAULT_ENCODE_SET,
                                ).to_string();
                                let name = display_name.to_string_lossy().into_owned();
                                tmpl << html! {
                                    tr {
                                        td { input(name="s", value=Raw(&link), type="checkbox") }
                                        td { a(href=Raw(&link)) { : name } }
                                        td {
                                            @ if !is_dir {
                                                : Raw(ByteSize::b(size as usize).to_string(false))
                                            }
                                        }
                                        td { : Raw(HumanTime::from(date).to_string()) }
                                    }
                                }
                            }
                        }
                    }
                    input(type="submit", value="Download");
                }
            }
        }
    }).into_string()
        .unwrap()
}

fn get_share_entry(entry: &fs::DirEntry) -> Result<Option<ShareEntry>, Error> {
    let metadata = entry.metadata().with_context(|_| {
        format!("Unable to read metadata of {}", entry.path().display())
    })?;
    let name = entry.file_name();
    let date = metadata.modified().with_context(|_| {
        format!(
            "Unable to read last modified time of {}",
            entry.path().display()
        )
    })?;
    if !is_hidden(&name) {
        Ok(Some(ShareEntry {
            name,
            is_dir: metadata.is_dir(),
            size: metadata.len(),
            date: date.into(),
        }))
    } else {
        Ok(None)
    }
}

fn get_dir_index(path: &Path) -> Result<Vec<ShareEntry>, Error> {
    let mut entries = fs::read_dir(&path)
        .with_context(|_| format!("Unable to read directory {}", path.display()))?
        .filter_map(|file| {
            file.map_err(|e| {
                error!("{}", e);
                e
            }).ok()
        })
        .collect::<Vec<_>>()
        .into_par_iter()
        .filter_map(|entry| match get_share_entry(&entry) {
            Ok(e) => e,
            Err(e) => {
                error!("{}", e);
                None
            }
        })
        .collect::<Vec<_>>();
    entries.par_sort_unstable_by_key(|e| (!e.is_dir, e.date));

    Ok(entries)
}

fn is_hidden(path: &OsStr) -> bool {
    path.as_bytes().starts_with(b".")
}

trait DurationExt {
    fn to_millis(&self) -> u64;
}

impl DurationExt for Duration {
    fn to_millis(&self) -> u64 {
        1000 * self.as_secs() + u64::from(self.subsec_nanos()) / (1000 * 1000)
    }
}
