#![feature(duration_as_u128)]
#![feature(try_from)]
#![feature(allocator_api)]
#![feature(global_allocator)]

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
extern crate tokio;
extern crate url;
extern crate walkdir;

use failure::{Error, ResultExt};
use futures::sync::mpsc;
use futures::{future, Future, Sink, Stream};
use futures_cpupool::CpuPool;
use http::header::{HeaderValue, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_serve::ChunkedReadFile;
use hyper::{service, Body, Server};
use mime_sniffer::MimeTypeSniffer;
use options::Options;
use os_str_ext::OsStrExt3;
use path_ext::PathExt;
use pipe::Pipe;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::slice::ParallelSliceMut;
use share_entry::ShareEntry;
use std::alloc::System;
use std::borrow::Cow;
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::fs::{self, DirEntry, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Instant;
use structopt::StructOpt;
use tar::Builder;
use url::{form_urlencoded, percent_encoding};
use walkdir::WalkDir;

mod index_page;
mod options;
mod os_str_ext;
mod path_ext;
mod pipe;
mod share_entry;

#[global_allocator]
static A: System = System;

type BoxedFuture = Box<Future<Item = Response<Body>, Error = std::io::Error> + Send + 'static>;

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
        let path_len = relative_path.len() as u64;
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

#[derive(Clone)]
struct RustyShare {
    options: Options,
    pool: CpuPool,
}

impl RustyShare {
    fn handle_get(
        &self,
        req: Request<Body>,
        path: PathBuf,
        path_: &Path,
    ) -> Result<BoxedFuture, Error> {
        let metadata = fs::metadata(&path)
            .with_context(|_| format!("Unable to read metadata of {}", path.display()))?;
        if metadata.is_dir() {
            if !path_.to_str().unwrap().ends_with('/') {
                let response = Response::builder()
                    .status(StatusCode::FOUND)
                    .header(
                        LOCATION,
                        HeaderValue::from_str(&(path_.to_str().unwrap().to_owned() + "/")).unwrap(),
                    )
                    .body(Body::empty())
                    .unwrap();
                Ok(Box::new(future::ok(response)))
            } else {
                let f = self.pool.spawn_fn(move || {
                    let enumerate_start = Instant::now();
                    let entries = get_dir_index(&path);
                    let enumerate_time = Instant::now() - enumerate_start;
                    let response = match entries {
                        Ok(entries) => {
                            let render_start = Instant::now();
                            let rendered = index_page::render(entries).unwrap();
                            let render_time = Instant::now() - render_start;
                            info!(
                                "enumerate: {} ms, render: {} ms",
                                enumerate_time.as_millis(),
                                render_time.as_millis()
                            );
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/html; charset=utf-8")
                                .body(Body::from(rendered))
                                .unwrap()
                        }
                        Err(e) => {
                            error!("{}", e);
                            Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::empty())
                                .unwrap()
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

    fn handle_post(&self, req: Request<Body>, path: PathBuf, path_: PathBuf) -> BoxedFuture {
        let pool = self.pool.clone();
        let b = req
            .into_body()
            .concat2()
            .and_then(move |b| {
                let mut files = Vec::new();
                for (name, value) in form_urlencoded::parse(&b) {
                    if name == "s" {
                        let value: PathBuf = OsStr::from_bytes(
                            std::borrow::Cow::<[u8]>::from(percent_encoding::percent_decode(
                                value.as_bytes(),
                            )).as_ref(),
                        ).into();
                        files.push(value)
                    } else {
                        let response = Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::empty())
                            .unwrap();
                        return Ok(response);
                    }
                }

                if files.is_empty() {
                    for entry in dir_entries(&path).unwrap() {
                        let path = entry.path();
                        let file_name = path.file_name().unwrap();
                        files.push(file_name.into());
                    }
                } else {
                    for file in &files {
                        info!("{}", file.display());
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
                tokio::spawn(f);

                Ok(Response::builder()
                    .header(
                        CONTENT_DISPOSITION,
                        HeaderValue::from_str(&format!(
                            "attachment; filename*=UTF-8''{}",
                            archive_name
                        )).unwrap(),
                    )
                    .header(
                        CONTENT_LENGTH,
                        HeaderValue::from_str(&archive_size.to_string()).unwrap(),
                    )
                    .header(CONTENT_TYPE, "application/x-tar")
                    .body(Body::wrap_stream(rx.map_err(|_| {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "incomplete",
                        ))
                    })))
                    .unwrap())
            })
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Interrupted, "incomplete"));
        Box::new(b)
    }

    fn get_archive_name(path_: &Path, files: &[PathBuf]) -> String {
        if files.len() == 1 {
            files[0]
                .with_extension("tar")
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        } else if path_.is_root() {
            String::from("archive.tar")
        } else {
            path_
                .with_extension("tar")
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        }
    }

    fn call(&self, req: Request<Body>) -> BoxedFuture {
        let root = self.options.root.as_path();
        let path_: PathBuf = OsStr::from_bytes(
            Cow::from(percent_encoding::percent_decode(
                req.uri().path().as_bytes(),
            )).as_ref(),
        ).into();
        let path = root.join(Path::new(&path_).strip_prefix("/").unwrap());
        info!("{} {}", req.method(), req.uri().path());
        match *req.method() {
            Method::GET => match self.handle_get(req, path, &path_) {
                Ok(response) => response,
                Err(e) => {
                    error!("{}", e);
                    let response = Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .unwrap();
                    Box::new(future::ok(response))
                }
            },
            Method::POST => self.handle_post(req, path, path_),
            _ => {
                let response = Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Body::empty())
                    .unwrap();
                Box::new(future::ok(response))
            }
        }
    }
}

fn run() -> Result<(), Error> {
    let options = Options::from_args();

    let addr = SocketAddr::new(
        options
            .address
            .parse::<IpAddr>()
            .with_context(|_| "Unable to parse listen address")?,
        options.port,
    );
    let rusty_share = RustyShare {
        options,
        pool: CpuPool::new_num_cpus(),
    };

    let server = Server::bind(&addr).serve(move || {
        let rusty_share = rusty_share.clone();
        service::service_fn(move |req| rusty_share.call(req))
    });

    info!("Listening on http://{}", server.local_addr());

    tokio::run(server.map_err(|e| eprintln!("server error: {}", e)));
    Ok(())
}

fn main() {
    pretty_env_logger::init();

    if let Err(e) = run() {
        error!("{}", e);
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
                error!(
                    "Unable to read metadata of {}: {}",
                    entry.path().display(),
                    e
                );
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
