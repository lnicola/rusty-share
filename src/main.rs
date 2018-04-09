extern crate bytes;
extern crate bytesize;
extern crate chrono;
extern crate chrono_humanize;
extern crate failure;
extern crate futures;
extern crate futures_cpupool;
#[macro_use]
extern crate horrorshow;
extern crate http;
extern crate http_serve;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate mime_sniffer;
extern crate pretty_env_logger;
extern crate rayon;
#[macro_use]
extern crate structopt;
extern crate tar;
extern crate tokio_core;
extern crate url;
extern crate walkdir;

use bytes::Bytes;
use bytesize::ByteSize;
use chrono::{DateTime, Local};
use chrono_humanize::HumanTime;
use duration_ext::DurationExt;
use failure::{Error, ResultExt};
use futures::sync::mpsc;
use futures::{future, stream, Future, Sink, Stream};
use futures_cpupool::CpuPool;
use horrorshow::helper::doctype;
use horrorshow::prelude::*;
use http::HeaderMap;
use http::header::CONTENT_TYPE;
use http_serve::ChunkedReadFile;
use hyper::header::{Charset, ContentDisposition, ContentLength, ContentType, DispositionParam,
                    DispositionType, Location};
use hyper::mime::{Mime, TEXT_HTML_UTF_8};
use hyper::server::{self, Http, Request, Response, Service};
use hyper::{Get, Post, StatusCode};
use mime_sniffer::MimeTypeSniffer;
use options::Options;
use path_ext::PathExt;
use pipe::Pipe;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::slice::ParallelSliceMut;
use std::borrow::Cow;
use std::convert::TryFrom;
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirEntry, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr};
#[cfg(not(target_os = "windows"))]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Instant;
use structopt::StructOpt;
use tar::Builder;
use tokio_core::reactor::{Core, Handle};
use url::{form_urlencoded, percent_encoding};
use walkdir::WalkDir;

mod duration_ext;
mod options;
mod path_ext;
mod pipe;

#[cfg(target_os = "windows")]
pub trait OsStrExt3 {
    fn from_bytes(b: &[u8]) -> &Self;
    fn as_bytes(&self) -> &[u8];
}

#[cfg(target_os = "windows")]
impl OsStrExt3 for OsStr {
    fn from_bytes(b: &[u8]) -> &Self {
        use std::mem;
        unsafe { mem::transmute(b) }
    }
    fn as_bytes(&self) -> &[u8] {
        self.to_str().map(|s| s.as_bytes()).unwrap()
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

#[cfg(windows)]
pub fn path2bytes(p: &Path) -> io::Result<Cow<[u8]>> {
    p.as_os_str()
        .to_str()
        .map(|s| s.as_bytes())
        .ok_or_else(|| other(&format!("path {} was not valid unicode", p.display())))
        .map(|bytes| {
            if bytes.contains(&b'\\') {
                // Normalize to Unix-style path separators
                let mut bytes = bytes.to_owned();
                for b in &mut bytes {
                    if *b == b'\\' {
                        *b = b'/';
                    }
                }
                Cow::Owned(bytes)
            } else {
                Cow::Borrowed(bytes)
            }
        })
}

#[cfg(any(unix, target_os = "redox"))]
/// On unix this will never fail
pub fn path2bytes(p: &Path) -> io::Result<Cow<[u8]>> {
    Ok(p.as_os_str().as_bytes()).map(Cow::Borrowed)
}

impl<W: Write> Archiver<W> {
    fn write_entry(&mut self, root: &Path, entry: &walkdir::DirEntry) -> Result<(), Error>
    where
        W: Write,
    {
        let metadata = entry
            .metadata()
            .with_context(|_| format!("Unable to read metadata for {}", entry.path().display()))?;
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
                .with_context(|_| format!("Unable to add {} to archive", entry.path().display()))?;
        } else {
            let mut file = File::open(&entry.path())
                .with_context(|_| format!("Unable to open {}", entry.path().display()))?;
            self.builder
                .append_file(&relative_path, &mut file)
                .with_context(|_| format!("Unable to add {} to archive", entry.path().display()))?;
        }

        Ok(())
    }

    fn entry_size(&mut self, root: &Path, entry: &walkdir::DirEntry) -> Result<u64, Error>
    where
        W: Write,
    {
        let metadata = entry
            .metadata()
            .with_context(|_| format!("Unable to read metadata for {}", entry.path().display()))?;
        let relative_path = entry.path().strip_prefix(&root).with_context(|_| {
            format!(
                "Unable to make path {} relative from {}",
                entry.path().display(),
                root.display()
            )
        })?;
        let mut header_len = 512;
        let path_len = path2bytes(relative_path).unwrap().len() as u64;
        if path_len > 100 {
            header_len += 512 + path_len;
            if path_len % 512 > 0 {
                header_len += 512 - path_len % 512;
            }
        }
        if !metadata.is_dir() {
            let mut len = metadata.len();
            if len % 512 > 0 {
                len += 512 - len % 512;
            }
            header_len += len;
        }
        Ok(header_len)
    }

    fn measure_entry<P, Q>(&mut self, root: P, entry: Q) -> u64
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
        W: Write,
    {
        let walkdir = WalkDir::new(root.as_ref().join(&entry));
        let entries = walkdir.into_iter().filter_entry(|e| !Self::is_hidden(e));
        let mut total_size = 0;
        for e in entries {
            match e {
                Ok(e) => match self.entry_size(root.as_ref(), &e) {
                    Err(e) => error!("{}", e),
                    Ok(size) => {
                        total_size += size;
                    }
                },
                Err(e) => error!("{}", e),
            }
        }
        total_size
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

    fn finish(&mut self) {
        if let Err(e) = self.builder.finish() {
            error!("{}", e);
        }
    }

    fn is_hidden(entry: &walkdir::DirEntry) -> bool {
        entry
            .file_name()
            .to_str()
            .map_or(true, |s| s.starts_with('.'))
    }
}

struct RustyShare {
    options: Options,
    handle: Handle,
    pool: CpuPool,
}

impl RustyShare {
    fn handle_get(
        &self,
        req: Request,
        path: PathBuf,
        path_: &Path,
    ) -> Result<<Self as Service>::Future, Error> {
        type Body = Box<Stream<Item = Bytes, Error = hyper::Error> + Send>;

        let metadata = fs::metadata(&path)
            .with_context(|_| format!("Unable to read metadata of {}", path.display()))?;
        if metadata.is_dir() {
            if !path_.to_str().unwrap().ends_with('/') {
                let response = Response::new()
                    .with_status(StatusCode::Found)
                    .with_header(Location::new(path_.to_str().unwrap().to_owned() + "/"));
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
            Ok(Box::new(self.pool.spawn_fn(move || {
                let mut f = File::open(&path)?;
                let mut buf = [0; 16];
                let len = f.read(&mut buf)?;
                let buf = &buf[0..len];
                f.seek(SeekFrom::Start(0))?;
                let mut headers = HeaderMap::new();
                if let Some(mime) = buf.sniff_mime_type() {
                    headers.insert(CONTENT_TYPE, mime.parse().unwrap());
                }
                let f = ChunkedReadFile::new(f, None, headers)?;
                Ok(http_serve::serve(f, &req))
            })))
        }
    }

    fn handle_post(
        &self,
        req: Request,
        path: PathBuf,
        path_: PathBuf,
    ) -> <Self as Service>::Future {
        type Body = Box<Stream<Item = Bytes, Error = hyper::Error> + Send>;

        let pool = self.pool.clone();
        let handle = self.handle.clone();
        let b = req.body().concat2().and_then(move |b| {
            let mut files = Vec::new();
            for (name, value) in form_urlencoded::parse(&b) {
                if name == "s" {
                    let value = OsStr::from_bytes(
                        std::borrow::Cow::<[u8]>::from(percent_encoding::percent_decode(
                            value.as_bytes(),
                        )).as_ref(),
                    ).into();
                    files.push(value)
                } else {
                    let response = Response::new().with_status(StatusCode::BadRequest);
                    return Ok(response);
                }
            }

            if files.is_empty() {
                for entry in dir_entries(&path).unwrap() {
                    let path = entry.path();
                    let file_name = path.file_name().unwrap();
                    files.push(file_name.into());
                }
            }

            let archive_name = Self::get_archive_name(&path_, &files);

            let (tx, rx) = mpsc::channel(10);
            let mut archive_size = 1024;
            let pipe = Pipe::new(tx.wait());
            let mut archiver = Archiver::new(Builder::new(pipe));
            for file in &files {
                archive_size += archiver.measure_entry(&path, file);
            }
            let f = pool.spawn_fn(move || {
                for file in &files {
                    archiver.add_to_archive(&path, file);
                }
                archiver.finish();

                future::ok::<_, ()>(())
            });
            handle.spawn(f);

            Ok(Response::new()
                .with_header(ContentDisposition {
                    disposition: DispositionType::Attachment,
                    parameters: vec![
                        DispositionParam::Filename(Charset::Iso_8859_1, None, archive_name),
                    ],
                })
                .with_header(ContentLength(archive_size))
                .with_header(ContentType("application/x-tar".parse::<Mime>().unwrap()))
                .with_body(Box::new(rx.map_err(|_| hyper::Error::Incomplete)) as Body))
        });
        Box::new(b)
    }

    fn get_archive_name(path_: &Path, files: &[PathBuf]) -> Vec<u8> {
        if files.len() == 1 {
            files[0]
                .with_extension("tar")
                .file_name()
                .unwrap()
                .as_bytes()
                .to_vec()
        } else if path_.is_root() {
            b"archive.tar".to_vec()
        } else {
            path_
                .with_extension("tar")
                .file_name()
                .unwrap()
                .as_bytes()
                .to_vec()
        }
    }
}

impl Service for RustyShare {
    type Request = Request;
    type Response = Response<Box<Stream<Item = Bytes, Error = Self::Error> + Send>>;
    type Error = hyper::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Request) -> Self::Future {
        let root = self.options.root.as_path();
        let path_: PathBuf = OsStr::from_bytes(
            std::borrow::Cow::<[u8]>::from(percent_encoding::percent_decode(req.path().as_bytes()))
                .as_ref(),
        ).into();
        let path = root.join(Path::new(&path_).strip_prefix("/").unwrap());
        info!("{:?}", req);
        match *req.method() {
            Get => match self.handle_get(req, path, &path_) {
                Ok(response) => response,
                Err(e) => {
                    error!("{}", e);
                    let response = Response::new().with_status(StatusCode::InternalServerError);
                    Box::new(future::ok(response))
                }
            },
            Post => self.handle_post(req, path, path_),
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

    let addr = SocketAddr::new(
        options
            .address
            .parse::<IpAddr>()
            .with_context(|_| "Unable to parse listen address")?,
        options.port,
    );
    let rusty_share = RustyShare {
        options,
        handle: handle.clone(),
        pool: CpuPool::new_num_cpus(),
    };

    let server = Http::new()
        .serve_addr_handle(&addr, &handle, server::const_service(rusty_share))
        .context("Unable to start server")?;
    info!("Listening on http://{}", server.incoming_ref().local_addr());

    let future = server.for_each(move |conn| {
        handle.spawn(conn.map(|_| ()).map_err(|e| error!("{}", e)));
        Ok(())
    });

    core.run(future).context("Unable to run server")?;
    Ok(())
}

fn main() {
    pretty_env_logger::init();

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
                                                : Raw(ByteSize::b(size).to_string(false))
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

impl<'a> TryFrom<&'a DirEntry> for ShareEntry {
    type Error = Error;

    fn try_from(value: &DirEntry) -> Result<Self, Self::Error> {
        let metadata = value
            .metadata()
            .with_context(|_| format!("Unable to read metadata of {}", value.path().display()))?;
        let date = metadata
            .modified()
            .with_context(|_| {
                format!(
                    "Unable to read last modified time of {}",
                    value.path().display()
                )
            })?
            .into();
        Ok(ShareEntry {
            name: value.file_name(),
            is_dir: metadata.is_dir(),
            size: metadata.len(),
            date,
        })
    }
}

fn dir_entries(path: &Path) -> Result<impl Iterator<Item = DirEntry>, Error> {
    Ok(fs::read_dir(path)
        .with_context(|_| format!("Unable to read directory {}", path.display()))?
        .filter_map(|file| {
            file.map_err(|e| {
                error!("{}", e);
                e
            }).ok()
        })
        .filter(|file| !is_hidden(&file.file_name())))
}

fn get_dir_index(path: &Path) -> Result<Vec<ShareEntry>, Error> {
    let mut entries = dir_entries(path)?
        .collect::<Vec<_>>()
        .into_par_iter()
        .filter_map(|entry| match ShareEntry::try_from(&entry) {
            Ok(e) => Some(e),
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
