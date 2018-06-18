#![feature(proc_macro)]
#![feature(generators)]
#![feature(duration_as_u128)]
#![feature(try_from)]
#![feature(allocator_api)]
#![feature(global_allocator)]

extern crate bytes;
extern crate bytesize;
extern crate chrono;
extern crate chrono_humanize;
extern crate failure;
extern crate futures_await as futures;
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
extern crate tokio_threadpool;
extern crate url;
extern crate walkdir;

use failure::{Error, ResultExt};
use fs_async::FileExt;
use futures::prelude::{async, await, Poll};
use futures::sync::mpsc;
use futures::{future, Future, Stream};
use http::header::CONTENT_TYPE;
use http::{HeaderMap, Method};
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
use std::cmp::Ordering;
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::fs::{self, DirEntry, File};
use std::io::{self, ErrorKind, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Instant;
use structopt::StructOpt;
use tar::Builder;
use url::{form_urlencoded, percent_encoding};
use walkdir::WalkDir;

mod fs_async;
mod index_page;
mod options;
mod os_str_ext;
mod path_ext;
mod pipe;
mod response;
mod share_entry;

#[global_allocator]
static A: System = System;

type Request = http::Request<Body>;
type Response = http::Response<Body>;

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

    fn entry_size(root: &Path, entry: &walkdir::DirEntry) -> Result<u64, Error>
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
                Ok(e) => match Self::entry_size(root.as_ref(), &e) {
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

    fn finish(&mut self) -> io::Result<()> {
        self.builder.finish()
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
}

#[async]
fn handle_get_dir(path: PathBuf, path_: PathBuf) -> Result<Response, Error> {
    if !path_.to_str().unwrap().ends_with('/') {
        Ok(response::found(&(path_.to_str().unwrap().to_owned() + "/")))
    } else {
        let rendered = await!(get_dir_index_async(path));
        match rendered {
            Ok(rendered) => Ok(response::page(rendered)),
            Err(e) => {
                error!("{}", e);
                Ok(response::not_found())
            }
        }
    }
}

#[async]
fn handle_get_file(req: Request, path: PathBuf) -> Result<Response, Error> {
    let mut file = await!(tokio::fs::File::open(path.clone()))?;
    let mut buf = [0; 16];
    let (file, buf) = await!(tokio::io::read_exact(file, buf))?;
    let (file, _) = await!(file.seek(SeekFrom::Start(0)))?;
    let file = file.into_std();

    let mut headers = HeaderMap::new();
    if let Some(mime) = buf.sniff_mime_type() {
        headers.insert(CONTENT_TYPE, mime.parse().unwrap());
    }
    let crf = ChunkedReadFile::new(file, None, headers)?;
    Ok(http_serve::serve(crf, &req))
}

#[async]
fn handle_get(req: Request, path: PathBuf, path_: PathBuf) -> Result<Response, Error> {
    match await!(fs_async::metadata(path.clone())) {
        Ok(metadata) => if metadata.is_dir() {
            await!(handle_get_dir(path, path_))
        } else {
            await!(handle_get_file(req, path))
        },
        Err(e) => {
            error!("{}", e);
            Ok(response::not_found())
        }
    }
}

fn decode_request(form: &[u8]) -> Option<Vec<PathBuf>> {
    let mut files = Vec::new();
    for (name, value) in form_urlencoded::parse(&form) {
        if name == "s" {
            let value: PathBuf = OsStr::from_bytes(
                Cow::<[u8]>::from(percent_encoding::percent_decode(value.as_bytes())).as_ref(),
            ).into();
            files.push(value)
        } else {
            return None;
        }
    }
    Some(files)
}

fn get_archive(path: PathBuf, files: Vec<PathBuf>) -> (u64, Body) {
    let (tx, rx) = mpsc::channel(0);
    let mut archive_size = 1024;
    let pipe = Pipe::new(tx);
    let mut archiver = Archiver::new(Builder::new(pipe));
    for file in &files {
        archive_size += archiver.measure_entry(&path, file);
    }
    let f = send_archive(archiver, path, files).map_err(|e: io::Error| error!("{}", e));
    tokio::spawn(f);

    let rx = rx
        .map_err(|_| Error::from(io::Error::new(ErrorKind::UnexpectedEof, "incomplete")).compat());

    (archive_size, Body::wrap_stream(rx))
}

fn send_archive<W>(
    archiver: Archiver<W>,
    path: PathBuf,
    files: Vec<PathBuf>,
) -> SendArchiveFuture<W>
where
    W: Write,
{
    SendArchiveFuture {
        archiver,
        path,
        files,
    }
}

struct SendArchiveFuture<W>
where
    W: Write,
{
    archiver: Archiver<W>,
    path: PathBuf,
    files: Vec<PathBuf>,
}

impl<W> Future for SendArchiveFuture<W>
where
    W: Write,
{
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        fs_async::blocking(|| {
            for file in &self.files {
                self.archiver.add_to_archive(&self.path, file);
            }
            self.archiver.finish()
        })
    }
}

#[async]
fn handle_post(req: Request, path: PathBuf, path_: PathBuf) -> Result<Response, Error> {
    let b = await!(req.into_body().concat2())?;

    let response = if let Some(mut files) = decode_request(&b) {
        if files.is_empty() {
            for entry in dir_entries(&path)? {
                let path = entry.path();
                let file_name = path.file_name().unwrap();
                files.push(file_name.into());
            }
        } else {
            for file in &files {
                info!("{}", file.display());
            }
        }

        let archive_name = get_archive_name(&path_, &files);

        let (content_length, body) = get_archive(path, files);
        response::archive(content_length, body, &archive_name)
    } else {
        response::bad_request()
    };

    Ok(response)
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

impl RustyShare {
    fn call(&self, req: Request) -> Box<Future<Item = Response, Error = Error> + Send + 'static> {
        let root = self.options.root.as_path();
        let path_ = PathBuf::from(OsStr::from_bytes(
            Cow::from(percent_encoding::percent_decode(
                req.uri().path().as_bytes(),
            )).as_ref(),
        ));
        let path = root.join(Path::new(&path_).strip_prefix("/").unwrap());
        info!("{} {}", req.method(), req.uri().path());
        match *req.method() {
            Method::GET => Box::new(handle_get(req, path, path_.clone())),
            Method::POST => Box::new(handle_post(req, path, path_)),
            _ => Box::new(future::ok(response::method_not_allowed())),
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
    let rusty_share = RustyShare { options };

    let server = Server::bind(&addr).serve(move || {
        let rusty_share = rusty_share.clone();
        service::service_fn(move |req| rusty_share.call(req).map_err(|e| e.compat()))
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

fn get_dir_entries(path: &Path) -> Result<Vec<ShareEntry>, Error> {
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

    entries.par_sort_unstable_by(|e1, e2| {
        if e1.is_dir && !e2.is_dir {
            Ordering::Less
        } else if !e1.is_dir && e2.is_dir {
            Ordering::Greater
        } else {
            e2.date.cmp(&e1.date)
        }
    });

    Ok(entries)
}

fn is_hidden(path: &OsStr) -> bool {
    path.as_bytes().starts_with(b".")
}

fn get_dir_index(path: &Path) -> Result<String, Error> {
    let enumerate_start = Instant::now();
    let entries = get_dir_entries(&path)?;
    let render_start = Instant::now();
    let enumerate_time = render_start - enumerate_start;
    let rendered = index_page::render(entries).unwrap();
    let render_time = Instant::now() - render_start;
    info!(
        "enumerate: {} ms, render: {} ms",
        enumerate_time.as_millis(),
        render_time.as_millis()
    );
    Ok(rendered)
}

fn get_dir_index_async(path: PathBuf) -> GetDirIndexFuture {
    GetDirIndexFuture { path }
}

struct GetDirIndexFuture {
    path: PathBuf,
}

impl Future for GetDirIndexFuture {
    type Item = String;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        fs_async::blocking(|| get_dir_index(&self.path))
    }
}
