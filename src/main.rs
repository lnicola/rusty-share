#![allow(proc_macro_derive_resolution_fallback)]

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate tower_web;

use cookie::Cookie;
use crate::archive::Archive;
use crate::blocking_future::{BlockingFuture, BlockingFutureTry};
use crate::db::{Conn, Store};
use crate::duration_ext::DurationExt;
use crate::error::Error;
use crate::options::{Command, Options};
use crate::os_str_ext::OsStrExt;
use crate::pipe::Pipe;
use crate::request_wrapper::RequestWrapper;
use crate::share_entry::ShareEntry;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sqlite::SqliteConnection;
use diesel::QueryResult;
use futures::sync::mpsc;
use futures::{future, Future, Stream};
use hex;
use http;
use http::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use http_serve;
use http_serve::ChunkedReadFile;
use hyper::Body;
use log::{error, info};
use mime_guess;
use pretty_env_logger;
use rand;
use rand::Rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::slice::ParallelSliceMut;
use scrypt;
use scrypt::ScryptParams;
use std::alloc::System;
use std::borrow::Cow;
use std::ffi::OsStr;
use std::fs::{self, DirEntry, File};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Instant;
use structopt::StructOpt;
use tar::Builder;
use tokio;
use tower_web::util::tuple::Either3;
use tower_web::ServiceBuilder;
use url::percent_encoding;
use walkdir::WalkDir;

mod archive;
mod blocking_future;
mod db;
mod duration_ext;
mod error;
mod options;
mod os_str_ext;
mod page;
mod pipe;
mod request_wrapper;
mod response;
mod share_entry;

#[global_allocator]
static A: System = System;

type Pool = r2d2::Pool<ConnectionManager<SqliteConnection>>;
type Response = http::Response<Body>;

struct RustyShare {
    root: PathBuf,
    pool: Option<Pool>,
}

fn handle_get_file(
    path: PathBuf,
    req: http::Request<()>,
) -> impl Future<Item = Response, Error = Error> {
    let mut headers = HeaderMap::new();
    {
        let extension = path.extension().and_then(OsStr::to_str).unwrap_or("");
        if let Some(mime) = mime_guess::get_mime_type_str(extension) {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static(mime));
        }
    }
    BlockingFutureTry::new(move || {
        File::open(&path)
            .and_then(|file| ChunkedReadFile::new(file, None, headers))
            .map_err(|e| Error::from_io(e, path.to_path_buf()))
    }).and_then(move |crf| future::ok(http_serve::serve(crf, &req)))
}

fn handle_get(
    path: PathBuf,
    uri_path: String,
    req: http::Request<()>,
) -> impl Future<Item = Response, Error = Error> {
    tokio::fs::metadata(path.clone())
        .then(|metadata| match metadata {
            Ok(metadata) => {
                if metadata.is_dir() {
                    if !uri_path.ends_with('/') {
                        Either3::A(future::ok(response::found(&(uri_path + "/"))))
                    } else {
                        Either3::B(
                            BlockingFuture::new(move || render_index(&path))
                                .map_err(|_| unreachable!()),
                        )
                    }
                } else {
                    Either3::C(handle_get_file(path, req))
                }
            }
            Err(e) => {
                error!("{}", Error::from_io(e, path.clone()));
                Either3::A(future::ok(response::not_found()))
            }
        })
        .map(|r| match r {
            Either3::A(r) | Either3::B(r) | Either3::C(r) => r,
        })
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

    let rx = rx.map_err(|_| Error::StreamCancelled);
    Body::wrap_stream(rx)
}

fn handle_post(files: Files, path: PathBuf) -> impl Future<Item = Response, Error = Error> {
    BlockingFutureTry::new(move || {
        let mut files = files
            .0
            .into_iter()
            .filter_map(|p| if p.0 == "s" { Some(p.1) } else { None })
            .map(|s| {
                let percent_decoded = Cow::from(percent_encoding::percent_decode(s.as_bytes()));
                PathBuf::from(OsStr::from_bytes(percent_decoded.as_ref()))
            })
            .collect::<Vec<_>>();
        if files.is_empty() {
            for entry in dir_entries(&path)? {
                let path = entry.path();
                let file_name = path.file_name().unwrap();
                files.push(file_name.into());
            }
        }
        let response = {
            let mut archive = Archive::new();
            for file in &files {
                info!("{}", file.display());
                let entries = WalkDir::new(path.join(file))
                    .into_iter()
                    .filter_entry(|e| !is_hidden(e.file_name()));
                for entry in entries {
                    if let Err(e) = entry
                        .map_err(Error::from)
                        .and_then(|entry| archive.add_entry(&path, entry))
                    {
                        error!("{}", e);
                    }
                }
            }

            let archive_name = get_archive_name(&path, &files);
            let archive_size = archive.size();
            let body = get_archive(archive);
            response::archive(archive_size, body, &archive_name)
        };
        Ok(response)
    })
}

fn get_archive_name(path_: &Path, files: &[PathBuf]) -> String {
    let file = if files.len() == 1 { &files[0] } else { path_ };
    file.with_extension("tar")
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| String::from("archive.tar"))
}

#[derive(Debug, Extract)]
struct LoginForm {
    user: String,
    pass: String,
}

#[derive(Debug, Extract)]
struct LoginQuery {
    redirect: Option<String>,
}

#[derive(Debug, Deserialize, Extract)]
#[serde(transparent)]
struct Files(Vec<(String, String)>);

impl_web! {
    impl RustyShare {
        fn check_auth(&self, path: &Path, cookie: Option<String>) -> Result<String, Response> {
            if let Some(ref pool) = self.pool {
                let redirect = || {
                    response::login_redirect(
                        &(String::from("/browse/") + path.to_string_lossy().as_ref()),
                        false,
                    )
                };
                let cookie = cookie.ok_or_else(redirect)?;
                let session_id = Cookie::parse(cookie).map_err(|e| {
                    error!("{}", e);
                    response::bad_request()
                })?;
                let session_id = hex::decode(session_id.value()).map_err(|e| {
                    error!("{}", e);
                    redirect()
                })?;
                let conn = pool.get().map_err(|e| {
                    error!("{}", e);
                    response::internal_server_error()
                })?;
                let store = Store::new(Conn::new(conn));
                let (_, user) = store
                    .lookup_session(&session_id)
                    .map_err(|e| {
                        error!("{}", e);
                        response::internal_server_error()
                    })?.ok_or_else(redirect)?;
                Ok(user)
            } else {
                Ok(String::new())
            }
        }

        #[get("/")]
        fn index(&self) -> Result<Response, ()> {
            Ok(response::found("/browse"))
        }

        #[get("/favicon.ico")]
        fn favicon(&self) -> Result<Response, ()> {
            Ok(response::not_found())
        }

        #[get("/login")]
        fn login_page(&self) -> Result<Response, ()> {
            if self.pool.is_some() {
                Ok(page::login(None))
            } else {
                Ok(response::not_found())
            }
        }

        #[post("/login")]
        fn login_action(&self, query_string: LoginQuery, body: LoginForm) -> Result<Response, ()> {
            if let Some(ref pool) = self.pool {
                let redirect = query_string
                    .redirect
                    .unwrap_or_else(|| String::from("/browse"));

                let store = match pool.get() {
                    Ok(conn) => Store::new(Conn::new(conn)),
                    Err(e) => {
                        error!("{}", e);
                        return Ok(response::internal_server_error());
                    }
                };

                let session = authenticate(&store, &body.user, &body.pass).unwrap();
                let response = if let Some(session_id) = session {
                    info!("Authenticating {}: success", body.user);
                    response::login_ok(hex::encode(&session_id), &redirect)
                } else {
                    info!("Authenticating {}: failed", body.user);
                    page::login(Some(
                        "Login failed. Please contact the site owner to reset your password.",
                    ))
                };

                Ok(response)
            } else {
                Ok(response::not_found())
            }
        }

        #[get("/browse")]
        fn browse_fallback(
            &self,
            cookie: Option<String>,
            request: RequestWrapper,
        ) -> Box<dyn Future<Item = Response, Error = Error> + Send + 'static> {
            self.browse(PathBuf::new(), cookie, request)
        }

        #[get("/browse/*path")]
        fn browse(
            &self,
            path: PathBuf,
            cookie: Option<String>,
            request: RequestWrapper,
        ) -> Box<dyn Future<Item = Response, Error = Error> + Send + 'static> {
            match self.check_auth(&path, cookie) {
                Ok(user) => {
                    info!("{} GET /browse/{}", user, path.display());
                }
                Err(response) => return Box::new(future::ok(response)),
            }

            let disk_path = self.root.as_path().join(&path);
            let request = request.into();
            let uri_path = request.uri().path().to_string();
            Box::new(handle_get(disk_path, uri_path, request))
        }

        #[post("/browse")]
        fn archive_fallback(
            &self,
            body: Files,
            cookie: Option<String>,
        ) -> Box<dyn Future<Item = Response, Error = Error> + Send + 'static> {
            self.archive(PathBuf::new(), body, cookie)
        }

        #[post("/browse/*path")]
        fn archive(
            &self,
            path: PathBuf,
            body: Files,
            cookie: Option<String>,
        ) -> Box<dyn Future<Item = Response, Error = Error> + Send + 'static> {
            match self.check_auth(&path, cookie) {
                Ok(user) => {
                    info!("{} POST /browse/{}", user, path.display());
                }
                Err(response) => return Box::new(future::ok(response)),
            }

            let disk_path = self.root.as_path().join(&path);
            Box::new(handle_post(body, disk_path))
        }
    }
}

fn run() -> Result<(), Error> {
    let options = Options::from_args();

    let mut pool = None;
    if let Some(ref db) = options.db {
        let manager = ConnectionManager::<SqliteConnection>::new(db.clone());
        let pool_ = Pool::builder().build(manager).expect("db pool");

        let should_initialize = !Path::new(&db).exists();
        let conn = Conn::new(pool_.get().unwrap());
        let store = Store::new(conn);
        pool = Some(pool_);

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
            .map_err(|e| Error::from_addr_parse(e, options.address.clone()))?,
        options.port,
    );
    println!("Listening on http://{}", addr);

    let rusty_share = RustyShare {
        root: options.root,
        pool,
    };

    ServiceBuilder::new()
        .resource(rusty_share)
        .run(&addr)
        .unwrap();

    // let server = Server::from_tcp(listener)?
    //     .tcp_nodelay(true)
    //     .serve(service)
    //     .map_err(|e| eprintln!("server error: {}", e));

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
        .map_err(|e| Error::from_io(e, path.to_path_buf()))?
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
                error!("{}", e);
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
                enumerate_time.to_millis(),
                render_time.to_millis()
            );
            rendered
        }
        Err(e) => {
            error!("{}", e);
            response::internal_server_error()
        }
    }
}

pub fn register_user(store: &Store, name: &str, password: &str) -> Result<i32, Error> {
    let params = ScryptParams::new(15, 8, 1).expect("recommended scrypt params should work");
    let hash = scrypt::scrypt_simple(password, &params)?;
    let user_id = store.insert_user(name, &hash)?;
    Ok(user_id)
}

pub fn reset_password(store: &Store, name: &str, password: &str) -> Result<(), Error> {
    let params = ScryptParams::new(15, 8, 1).expect("recommended scrypt params should work");
    let hash = scrypt::scrypt_simple(password, &params)?;
    store.update_password_by_name(name, &hash)?;
    Ok(())
}

pub fn authenticate(store: &Store, name: &str, password: &str) -> QueryResult<Option<[u8; 16]>> {
    let user = store
        .find_user(name)?
        .and_then(|user| {
            scrypt::scrypt_check(password, &user.password)
                .map(|_| user)
                .map_err(|e| error!("Password verification failed for user {}: {}", name, e))
                .ok()
        })
        .map(|user| {
            let session_id = rand::thread_rng().gen::<[u8; 16]>();
            if let Err(e) = store.create_session(&session_id, user.id) {
                error!("Error saving session for user id {}: {}", user.id, e);
            }

            session_id
        });

    Ok(user)
}
