#![feature(rust_2018_idioms)]
#![feature(generators)]
#![feature(duration_as_u128)]
#![feature(try_from)]
#![feature(use_extern_macros)]
#![allow(proc_macro_derive_resolution_fallback)]
#![allow(dead_code)]

extern crate bytes;
extern crate bytesize;
extern crate chrono;
extern crate chrono_humanize;
extern crate cookie;
#[macro_use]
extern crate diesel;
extern crate failure;
extern crate futures_await as futures;
extern crate horrorshow;
extern crate http;
extern crate http_serve;
extern crate hyper;
extern crate libpasta;
extern crate log;
extern crate mime_sniffer;
extern crate pretty_env_logger;
extern crate rand;
extern crate rayon;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate hex;
extern crate serde_urlencoded;
extern crate structopt;
extern crate tar;
extern crate time;
extern crate tokio;
extern crate tokio_fs;
extern crate tokio_threadpool;
extern crate url;
extern crate walkdir;

use archive::Archive;
use blocking_future::{BlockingFuture, BlockingFutureTry};
use cookie::Cookie;
use db::Store;
use diesel::QueryResult;
use failure::{Error, ResultExt};
use futures::prelude::{async, await};
use futures::sync::mpsc;
use futures::{future, Future, Stream};
use http::header::{CONTENT_TYPE, COOKIE};
use http::{HeaderMap, Method};
use http_serve::ChunkedReadFile;
use hyper::{service, Body, Server};
use libpasta::HashUpdate;
use log::{error, info, log};
use mime_sniffer::MimeTypeSniffer;
use options::{Command, Options};
use os_str_ext::OsStrExt3;
use pipe::Pipe;
use rand::Rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::slice::ParallelSliceMut;
use share_entry::ShareEntry;
use std::alloc::System;
use std::borrow::Cow;
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::fs::{self, DirEntry};
use std::io::{self, ErrorKind, SeekFrom};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Instant;
use structopt::StructOpt;
use tar::Builder;
use url::{form_urlencoded, percent_encoding};
use walkdir::WalkDir;

mod archive;
mod blocking_future;
mod db;
mod options;
mod os_str_ext;
mod page;
mod pipe;
mod response;
mod share_entry;

#[global_allocator]
static A: System = System;

type Request = http::Request<Body>;
type Response = http::Response<Body>;

#[derive(Clone)]
struct RustyShare {
    options: Options,
}

#[async]
fn handle_get_dir(path: PathBuf, path_: PathBuf) -> Result<Response, Error> {
    if !path_.to_str().unwrap().ends_with('/') {
        Ok(response::found(&(path_.to_str().unwrap().to_owned() + "/")))
    } else {
        let rendered = await!(BlockingFuture::new(move || render_index(&path))).unwrap();
        Ok(rendered)
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
    match await!(tokio_fs::metadata(path.clone())) {
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

fn decode_path(p: &str) -> PathBuf {
    OsStr::from_bytes(Cow::from(percent_encoding::percent_decode(p.as_bytes())).as_ref()).into()
}

fn decode_request(form: &[u8]) -> Option<Vec<PathBuf>> {
    let mut files = Vec::new();
    for (name, value) in form_urlencoded::parse(&form) {
        if name == "s" {
            files.push(decode_path(&value))
        } else {
            return None;
        }
    }
    Some(files)
}

fn get_archive(archive: Archive) -> Body {
    let (tx, rx) = mpsc::channel(0);
    let pipe = Pipe::new(tx);
    let mut builder = Builder::new(pipe);
    let f = BlockingFutureTry::new(move || {
        for entry in archive.entries() {
            if let Err(e) = entry.write_to(&mut builder) {
                error!("{}", e);
            }
        }
        builder.finish()
    }).map_err(|e| error!("{}", e));
    tokio::spawn(f);

    let rx = rx
        .map_err(|_| Error::from(io::Error::new(ErrorKind::UnexpectedEof, "incomplete")).compat());

    Body::wrap_stream(rx)
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
        }

        let mut archive = Archive::new();
        for file in &files {
            info!("{}", file.display());
            let entries = WalkDir::new(path.join(file))
                .into_iter()
                .filter_entry(|e| !is_hidden(e.file_name()));
            for entry in entries {
                if let Err(e) = entry
                    .map_err(|e| e.into())
                    .and_then(|entry| archive.add_entry(&path, &entry))
                {
                    error!("{}", e);
                }
            }
        }

        let archive_name = get_archive_name(&path_, &files);
        let archive_size = archive.size();
        let body = get_archive(archive);
        response::archive(archive_size, body, &archive_name)
    } else {
        response::bad_request()
    };

    Ok(response)
}

#[async]
fn handle_login(req: Request, store: Store) -> Result<Response, Error> {
    let b = await!(req.into_body().concat2())?;
    let form = serde_urlencoded::from_bytes::<LoginForm>(&b).unwrap();
    let session = authenticate(&store, &form.user, &form.pass).unwrap();
    let response = if let Some(session_id) = session {
        info!("Authenticating {}: success", form.user);
        response::login_ok(hex::encode(&session_id))
    } else {
        info!("Authenticating {}: failed", form.user);
        page::login(Some(
            "Login failed. Please contact the site owner to reset your password.",
        ))
    };

    Ok(response)
}

fn get_archive_name(path_: &Path, files: &[PathBuf]) -> String {
    let file = if files.len() == 1 { &files[0] } else { path_ };
    file.with_extension("tar")
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| String::from("archive.tar"))
}

#[derive(Deserialize, Debug)]
struct LoginForm {
    user: String,
    pass: String,
}

impl RustyShare {
    fn call(&self, req: Request) -> Box<Future<Item = Response, Error = Error> + Send + 'static> {
        if let Some(ref db) = self.options.db {
            let is_login = req.uri().path() == "/login";
            if is_login && *req.method() == Method::GET {
                info!("{} {}", req.method(), req.uri().path());
                return Box::new(future::ok(page::login(None)));
            }

            let store = match db::establish_connection(&db) {
                Ok(conn) => Store::new(conn),
                Err(e) => {
                    info!("{} {}", req.method(), req.uri().path());
                    error!("{}", e);
                    return Box::new(future::ok(response::internal_server_error()));
                }
            };

            if is_login {
                info!("{} {}", req.method(), req.uri().path());
                if *req.method() == Method::POST {
                    return Box::new(handle_login(req, store));
                } else {
                    return Box::new(future::ok(response::method_not_allowed()));
                }
            }

            if let Some(cookie) = req.headers().get(COOKIE) {
                let session_id = Cookie::parse(cookie.to_str().unwrap()).unwrap();
                match store
                    .lookup_session(&hex::decode(session_id.value()).unwrap())
                    .unwrap()
                {
                    Some((_, user)) => info!("{} {} {}", user, req.method(), req.uri().path()),
                    None => {
                        info!("{} {}", req.method(), req.uri().path());
                        return Box::new(future::ok(response::login_redirect(true)));
                    }
                }
            } else {
                info!("{} {}", req.method(), req.uri().path());
                return Box::new(future::ok(response::login_redirect(false)));
            }
        }

        let root = self.options.root.as_path();
        let path_ = decode_path(req.uri().path());
        let path = root.join(Path::new(&path_).strip_prefix("/").unwrap());
        match *req.method() {
            Method::GET => Box::new(handle_get(req, path, path_.clone())),
            Method::POST => Box::new(handle_post(req, path, path_)),
            _ => Box::new(future::ok(response::method_not_allowed())),
        }
    }
}

fn run() -> Result<(), Error> {
    let options = Options::from_args();

    if let Some(ref db) = options.db {
        let should_initialize = !Path::new(&db).exists();
        let store = Store::new(db::establish_connection(db).unwrap());
        if should_initialize {
            store
                .initialize_database()
                .expect("unable to create database");
        }

        match options.command {
            Some(Command::Register { ref user, ref pass }) => {
                register_user(&store, &user, &pass)?;
                return Ok(());
            }
            Some(Command::ResetPassword { ref user, ref pass }) => {
                reset_password(&store, &user, &pass)?;
                return Ok(());
            }
            None => {}
        }
    }

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

    println!("Listening on http://{}", server.local_addr());

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

    entries.par_sort_unstable_by(|e1, e2| (e2.is_dir(), e2.date()).cmp(&(e1.is_dir(), e1.date())));

    Ok(entries)
}

pub fn is_hidden(path: &OsStr) -> bool {
    path.as_bytes().starts_with(b".")
}

fn render_index(path: &Path) -> Response {
    let enumerate_start = Instant::now();
    match get_dir_entries(&path) {
        Ok(entries) => {
            let render_start = Instant::now();
            let enumerate_time = render_start - enumerate_start;
            let rendered = page::index(&entries);
            let render_time = Instant::now() - render_start;
            info!(
                "enumerate: {} ms, render: {} ms",
                enumerate_time.as_millis(),
                render_time.as_millis()
            );
            rendered
        }
        Err(e) => {
            error!("{}", e);
            response::internal_server_error()
        }
    }
}

pub fn register_user(store: &Store, name: &str, password: &str) -> QueryResult<i32> {
    store.insert_user(name, &libpasta::hash_password(password))
}

pub fn reset_password(store: &Store, name: &str, password: &str) -> QueryResult<()> {
    store.update_password_by_name(name, &libpasta::hash_password(password))?;
    Ok(())
}

pub fn authenticate(store: &Store, name: &str, password: &str) -> QueryResult<Option<[u8; 16]>> {
    let user = store
        .find_user(name)?
        .and_then(
            |user| match libpasta::verify_password_update_hash(&user.password, &password) {
                HashUpdate::Verified(Some(new_hash)) => {
                    if let Err(e) = store.update_password_by_id(user.id, &new_hash) {
                        error!("Error migrating password for user id {}: {}", user.id, e);
                    }
                    Some(user)
                }
                HashUpdate::Verified(None) => Some(user),
                HashUpdate::Failed => None,
            },
        )
        .map(|user| {
            let session_id = rand::thread_rng().gen::<[u8; 16]>();
            if let Err(e) = store.create_session(&session_id, user.id) {
                error!("Error saving session for user id {}: {}", user.id, e);
            }

            session_id
        });

    Ok(user)
}
