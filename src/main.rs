#![allow(proc_macro_derive_resolution_fallback)]

#[macro_use]
extern crate diesel;

use archive::Archive;
use authentication::Authentication;
use blocking_future::{BlockingFuture, BlockingFutureTry};
use db::{Conn, Store};
use db_store::DbStore;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sqlite::SqliteConnection;
use diesel::QueryResult;
use either::{Either2, Either3, Either6};
use error::Error;
use futures::{future, Future, Stream};
use headers::{Cookie, HeaderMapExt};
use hex;
use http::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use http::request::Parts;
use http::{Method, Request};
use http_serve::{self, ChunkedReadFile};
use hyper::service::service_fn;
use hyper::{Body, Server};
use log::{error, info};
use mime_guess;
use options::{Command, Options};
use os_str_ext::OsStrExt;
use pipe::Pipe;
use pretty_env_logger;
use rand::{self, Rng};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::slice::ParallelSliceMut;
use scrypt::{self, ScryptParams};
use share::Share;
use share_entry::ShareEntry;
use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirEntry, File};
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::str;
use std::sync::Arc;
use std::time::Instant;
use structopt::StructOpt;
use tar::Builder;
use tokio;
use tokio_sync::mpsc;
use url::{form_urlencoded, percent_encoding};
use walkdir::WalkDir;

mod archive;
mod authentication;
mod blocking_future;
mod db;
mod db_store;
mod either;
mod error;
mod options;
mod os_str_ext;
mod page;
mod pipe;
mod response;
mod share;
mod share_entry;

type Pool = r2d2::Pool<ConnectionManager<SqliteConnection>>;
type Response = http::Response<Body>;

pub struct Config {
    pool: Option<Pool>,
}

struct RustyShare {
    root: PathBuf,
    has_db: bool,
}

fn get_archive(archive: Archive) -> Body {
    let (tx, rx) = mpsc::channel(1);
    let pipe = Pipe::new(tx);
    let mut builder = Builder::new(pipe);
    let f = BlockingFutureTry::new(move || {
        for entry in archive.entries() {
            if let Err(e) = entry.write_to(&mut builder) {
                error!("{}", e);
            }
        }
        builder.finish()
    })
    .map_err(|e| error!("{}", e));
    tokio::spawn(f);

    let rx = rx.map_err(|_| Error::StreamCancelled);
    Body::wrap_stream(rx)
}

fn get_archive_name(path_: &Path, files: &[PathBuf], single_dir: bool) -> String {
    if files.len() == 1 {
        if single_dir {
            files[0]
                .file_name()
                .map(|f| f.to_string_lossy().into_owned() + ".tar")
                .unwrap_or_else(|| String::from("archive.tar"))
        } else {
            files[0]
                .with_extension("tar")
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(|| String::from("archive.tar"))
        }
    } else {
        path_
            .file_name()
            .map(|f| f.to_string_lossy().into_owned() + ".tar")
            .unwrap_or_else(|| String::from("archive.tar"))
    }
}

struct LoginForm {
    user: String,
    pass: String,
}

impl LoginForm {
    pub fn from_bytes(input: &[u8]) -> Self {
        let mut user = String::new();
        let mut pass = String::new();
        for p in form_urlencoded::parse(input) {
            if p.0 == "user" {
                user = p.1.into_owned();
            } else if p.0 == "pass" {
                pass = p.1.into_owned();
            }
        }
        Self { user, pass }
    }

    fn from_body(body: Body) -> impl Future<Item = Self, Error = Error> {
        body.concat2()
            .map_err(|_e| Error::StreamCancelled)
            .and_then(move |body| {
                let vec = body.to_vec();
                let form = Self::from_bytes(vec.as_slice());
                future::ok(form)
            })
    }
}

struct Files {
    s: Vec<String>,
}

impl Files {
    pub fn from_bytes(input: &[u8]) -> Self {
        let mut files = vec![];
        for p in form_urlencoded::parse(input) {
            if p.0 == "s" {
                files.push(p.1.into_owned());
            }
        }
        Self { s: files }
    }

    fn from_body(body: Body) -> impl Future<Item = Self, Error = Error> {
        body.concat2()
            .map_err(|_e| Error::StreamCancelled)
            .and_then(move |body| {
                let vec = body.to_vec();
                let files = Files::from_bytes(vec.as_slice());
                future::ok(files)
            })
    }
}

impl RustyShare {
    fn lookup_share(&self, store: &DbStore, name: &str) -> Result<PathBuf, Response> {
        if let Some(ref store) = store.0 {
            let path = store
                .lookup_share(name)
                .map_err(|e| {
                    error!("{}", e);
                    response::internal_server_error()
                })?
                .ok_or_else(response::not_found)?;
            Ok(path)
        } else if name == "public" {
            Ok(self.root.clone())
        } else {
            Err(response::not_found())
        }
    }

    fn get_shares(&self, store: &DbStore) -> Result<Vec<Share>, Response> {
        if let Some(ref store) = store.0 {
            let shares = store
                .get_share_names()
                .map_err(|e| {
                    error!("{}", e);
                    response::internal_server_error()
                })?
                .into_iter()
                .map(Share::new)
                .collect::<Vec<_>>();
            Ok(shares)
        } else {
            Ok(vec![Share::new(String::from("public"))])
        }
    }

    fn index(&self) -> impl Future<Item = Response, Error = Error> {
        future::ok(response::found("/browse/"))
    }

    fn favicon(&self) -> impl Future<Item = Response, Error = Error> {
        future::ok(response::not_found())
    }

    fn login(
        &self,
        config: &Config,
        parts: &Parts,
        body: Body,
    ) -> impl Future<Item = Response, Error = Error> {
        if parts.method == &Method::GET {
            Either2::A(self.login_page())
        } else {
            let store = DbStore::extract(&config).unwrap();

            let mut redirect = None;
            for p in form_urlencoded::parse(parts.uri.query().unwrap_or("").as_bytes()) {
                if p.0 == "redirect" {
                    redirect = Some(p.1.into_owned());
                }
            }

            let fut = LoginForm::from_body(body).and_then(move |form| {
                let res = Self::login_action(store, redirect, &form.user, &form.pass);
                future::ok(res)
            });
            Either2::B(fut)
        }
        .map(|r| r.into_inner())
    }

    fn browse_or_archive(
        &self,
        store: &DbStore,
        authentication: Authentication,
        parts: &Parts,
        body: Body,
    ) -> impl Future<Item = Response, Error = Error> {
        let pb = decode(parts.uri.path())
            .map(|s| {
                PathBuf::from(s)
                    .components()
                    .skip(2)
                    .map(|c| Path::new(c.as_os_str()))
                    .collect::<PathBuf>()
            })
            .and_then(|pb| {
                if check_for_path_traversal(&pb) {
                    Ok(pb)
                } else {
                    Err(Error::InvalidArgument)
                }
            });
        match pb {
            Ok(pb) => {
                let share = pb
                    .components()
                    .next()
                    .unwrap()
                    .as_os_str()
                    .to_str()
                    .unwrap()
                    .to_string();

                let path = pb
                    .components()
                    .skip(1)
                    .map(|c| Path::new(c.as_os_str()))
                    .collect::<PathBuf>();

                match self.lookup_share(store, &share) {
                    Ok(share) => match authentication {
                        Authentication::User(user) => {
                            if parts.method == Method::GET {
                                let request = request_from_parts(&parts);
                                let res = RustyShare::browse(share, path, request, &user);
                                Either3::C(res)
                            } else {
                                let fut = Files::from_body(body).and_then(move |files| {
                                    RustyShare::archive(share, path, files, &user)
                                });
                                Either3::B(fut)
                            }
                        }
                        Authentication::Error(res) => Either3::A(future::ok(res)),
                    },
                    Err(res) => Either3::A(future::ok(res)),
                }
            }
            Err(e) => {
                error!("{}", e);
                Either3::A(future::ok(response::bad_request()))
            }
        }
        .map(|r| r.into_inner())
    }

    fn login_page(&self) -> impl Future<Item = Response, Error = Error> {
        if self.has_db {
            future::ok(page::login(None))
        } else {
            future::ok(response::not_found())
        }
    }

    fn login_action(store: DbStore, redirect: Option<String>, user: &str, pass: &str) -> Response {
        if let Some(ref store) = store.0 {
            let redirect = redirect.unwrap_or_else(|| String::from("/browse/"));

            let session = authenticate(&store, user, pass).unwrap();
            let response = if let Some(session_id) = session {
                info!("Authenticating {}: success", user);
                response::login_ok(hex::encode(&session_id), &redirect)
            } else {
                info!("Authenticating {}: failed", user);
                page::login(Some(
                    "Login failed. Please contact the site owner to reset your password.",
                ))
            };

            response
        } else {
            response::not_found()
        }
    }

    fn browse_shares(
        &self,
        store: &DbStore,
        authentication: Authentication,
    ) -> impl Future<Item = Response, Error = Error> {
        let res = match authentication {
            Authentication::User(user) => {
                info!("{} GET /browse/", user);
                match self.get_shares(store) {
                    Ok(shares) => page::shares(&shares),
                    Err(response) => response,
                }
            }
            Authentication::Error(res) => res,
        };
        future::ok(res)
    }

    fn browse(
        share: PathBuf,
        path: PathBuf,
        request: Request<()>,
        user: &str,
    ) -> impl Future<Item = Response, Error = Error> {
        info!(
            "{} GET /browse/{}/{}",
            user,
            share.display(),
            path.display()
        );
        let disk_path = share.join(&path);
        let uri_path = request.uri().path().to_string();

        tokio_fs::metadata(disk_path.clone())
            .then(|metadata| match metadata {
                Ok(metadata) => {
                    if metadata.is_dir() {
                        if !uri_path.ends_with('/') {
                            Either3::A(future::ok(response::found(&(uri_path + "/"))))
                        } else {
                            let fut = BlockingFuture::new(move || render_index(&disk_path))
                                .map_err(|_| unreachable!());
                            Either3::B(fut)
                        }
                    } else {
                        let mut headers = HeaderMap::new();
                        let extension = disk_path.extension().and_then(OsStr::to_str).unwrap_or("");
                        if let Some(mime) = mime_guess::get_mime_type_str(extension) {
                            headers.insert(CONTENT_TYPE, HeaderValue::from_static(mime));
                        }
                        let fut = BlockingFutureTry::new(move || {
                            File::open(&disk_path)
                                .and_then(|file| ChunkedReadFile::new(file, None, headers))
                                .map_err(|e| Error::from_io(e, disk_path))
                        })
                        .and_then(move |crf| future::ok(http_serve::serve(crf, &request)));

                        Either3::C(fut)
                    }
                }
                Err(e) => {
                    error!("{}", Error::from_io(e, disk_path));
                    Either3::A(future::ok(response::not_found()))
                }
            })
            .map(|r| r.into_inner())
    }

    fn archive(
        share: PathBuf,
        path: PathBuf,
        files: Files,
        user: &str,
    ) -> impl Future<Item = Response, Error = Error> {
        info!(
            "{} POST /browse/{}/{}",
            user,
            share.display(),
            path.display()
        );
        let disk_path = share.join(&path);
        BlockingFutureTry::new(move || {
            let mut files = files.s.iter().map(PathBuf::from).collect::<Vec<_>>();
            if files.is_empty() {
                for entry in dir_entries(&disk_path)? {
                    let path = entry.path();
                    let file_name = path.file_name().unwrap();
                    files.push(file_name.into());
                }
            }
            let response = {
                let mut archive = Archive::new();
                for file in &files {
                    info!("{}", file.display());
                    let entries = WalkDir::new(disk_path.join(file))
                        .into_iter()
                        .filter_entry(|e| !is_hidden(e.file_name()));
                    for entry in entries {
                        if let Err(e) = entry
                            .map_err(Error::from)
                            .and_then(|entry| archive.add_entry(&disk_path, entry))
                        {
                            error!("{}", e);
                        }
                    }
                }

                let single_dir =
                    files.len() == 1 && fs::metadata(disk_path.join(&files[0]))?.is_dir();
                let archive_name = get_archive_name(&disk_path, &files, single_dir);
                let archive_size = archive.size();
                let body = get_archive(archive);
                response::archive(archive_size, body, &archive_name)
            };
            Ok(response)
        })
    }
}

fn handle_request(
    config: &Arc<Config>,
    rusty_share: &Arc<RustyShare>,
    req: Request<Body>,
) -> impl Future<Item = Response, Error = Error> {
    let (parts, body) = req.into_parts();
    match (&parts.method, parts.uri.path()) {
        (&Method::GET, "/") => {
            let res = rusty_share.index();
            Either6::C(res)
        }
        (&Method::GET, "/login") | (&Method::POST, "/login") => {
            let res = rusty_share.login(&config, &parts, body);
            Either6::E(res)
        }
        (&Method::GET, "/favicon.ico") => {
            let res = rusty_share.favicon();
            Either6::F(res)
        }
        (&Method::GET, "/browse/") => {
            let store = DbStore::extract(&config).unwrap();
            let authentication =
                Authentication::extract(&store, &parts.uri, parts.headers.typed_get::<Cookie>());
            let fut = rusty_share.browse_shares(&store, authentication);
            Either6::B(fut)
        }
        (&Method::GET, path) | (&Method::POST, path) if path.starts_with("/browse/") => {
            let store = DbStore::extract(&config).unwrap();
            let authentication =
                Authentication::extract(&store, &parts.uri, parts.headers.typed_get::<Cookie>());
            let fut = rusty_share.browse_or_archive(&store, authentication, &parts, body);
            Either6::D(fut)
        }
        _ => Either6::A(future::ok(response::bad_request())),
    }
    .map(|r| r.into_inner())
}

fn run() -> Result<(), Error> {
    let options = Options::from_args();

    let mut pool = None;
    if let Some(ref db) = options.db {
        let should_initialize = !Path::new(&db).exists();

        let manager = ConnectionManager::<SqliteConnection>::new(db.clone());
        let pool_ = Pool::builder().build(manager).expect("db pool");

        let conn = Conn::new(pool_.get().unwrap());
        let store = Store::new(conn);
        pool = Some(pool_);

        if should_initialize {
            info!("Initializing database");
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
            Some(Command::CreateShare { ref name, ref path }) => {
                create_share(&store, &name, &path)?;
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

    let has_db = pool.is_some();
    let config = Config { pool };

    let rusty_share = RustyShare {
        root: options.root,
        has_db,
    };

    let rusty_share = Arc::new(rusty_share);
    let config = Arc::new(config);

    let new_svc = move || {
        let rusty_share = Arc::clone(&rusty_share);
        let config = Arc::clone(&config);
        service_fn(move |req: Request<Body>| handle_request(&config, &rusty_share, req))
    };

    let listener = std::net::TcpListener::bind(&addr)?;

    let server = Server::from_tcp(listener)?
        .tcp_nodelay(true)
        .serve(new_svc)
        .map_err(|e| eprintln!("server error: {}", e));

    hyper::rt::run(server);

    Ok(())
}

fn osstr_from_bytes(bytes: &[u8]) -> Result<&OsStr, Error> {
    // NOTE: this is too conservative, as we are rejecting valid paths on Unix
    str::from_utf8(bytes)
        .map_err(|_e| Error::InvalidArgument)
        .map(|s| OsStr::new(s))
}

fn decode(s: &str) -> Result<OsString, Error> {
    let percent_decoded = Cow::from(percent_encoding::percent_decode(s.as_bytes()));
    Ok(osstr_from_bytes(percent_decoded.as_ref())?.to_os_string())
}

fn request_from_parts(req: &Parts) -> Request<()> {
    let mut request = Request::builder()
        .method(req.method.clone())
        .version(req.version)
        .uri(req.uri.clone())
        .body(())
        .unwrap();
    request.headers_mut().extend(req.headers.clone());
    request
}

// https://www.owasp.org/index.php/Path_Traversal
fn check_for_path_traversal(path: &Path) -> bool {
    let mut depth = 0u32;
    for c in path.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => {
                return false;
            }
            Component::CurDir => {
                // no-op
            }
            Component::ParentDir => {
                depth = match depth.checked_sub(1) {
                    Some(v) => v,
                    None => return false,
                }
            }
            Component::Normal(_) => {
                depth += 1;
            }
        }
    }

    true
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
            })
            .ok()
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

pub fn create_share(store: &Store, name: &str, path: &str) -> Result<(), Error> {
    store.create_share(name, &path)?;
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
