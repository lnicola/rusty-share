#[macro_use]
extern crate diesel;

use archive::Archive;
use authentication::Authentication;
use blocking_future::{BlockingFuture, BlockingFutureTry};
use db::SqliteStore;
use error::Error;
use futures::{future, Future, Stream};
use headers::{Cookie, HeaderMapExt};
use hex;
use http::header::CONTENT_TYPE;
use http::request::Parts;
use http::{HeaderMap, HeaderValue, Method, Request};
use http_serve::{self, ChunkedReadFile};
use hyper::service::service_fn;
use hyper::{Body, Server};
use log::{error, info};
use mime_guess;
use options::{Command, Options};
use pipe::Pipe;
use pretty_env_logger;
use rand::{self, Rng};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::slice::ParallelSliceMut;
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
use url::form_urlencoded;
use walkdir::WalkDir;

mod archive;
mod authentication;
mod blocking_future;
mod db;
mod error;
mod options;
mod page;
mod pipe;
mod response;
mod scrypt_simple;
mod share;
mod share_entry;

type Response = http::Response<Body>;
type BoxedFuture<T, E> = Box<dyn Future<Item = T, Error = E> + Send>;

struct RustyShare {
    root: PathBuf,
    store: Option<SqliteStore>,
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
    pub fn from_bytes<T: AsRef<[u8]>>(input: T) -> Self {
        let mut user = String::new();
        let mut pass = String::new();
        for p in form_urlencoded::parse(input.as_ref()) {
            if p.0 == "user" {
                user = p.1.into_owned();
            } else if p.0 == "pass" {
                pass = p.1.into_owned();
            }
        }
        Self { user, pass }
    }

    fn from_body(body: Body) -> impl Future<Item = Self, Error = Error> {
        vec_from_body(body).map(Self::from_bytes)
    }
}

fn files_from_body(body: Body) -> impl Future<Item = Vec<String>, Error = Error> {
    vec_from_body(body).map(|buf| {
        form_urlencoded::parse(buf.as_ref())
            .filter_map(|p| {
                if p.0 == "s" {
                    let percent_decoded =
                        Cow::from(percent_encoding::percent_decode_str(p.1.as_ref()));
                    String::from_utf8(percent_decoded.into_owned()).ok()
                } else {
                    None
                }
            })
            .collect()
    })
}

fn vec_from_body(body: Body) -> impl Future<Item = Vec<u8>, Error = Error> {
    body.concat2()
        .map_err(|_e| Error::StreamCancelled)
        .map(|body| body.to_vec())
}

impl RustyShare {
    fn lookup_share(
        root: PathBuf,
        store: &Option<SqliteStore>,
        name: &str,
        user_id: Option<i32>,
    ) -> Result<PathBuf, Response> {
        if let Some(store) = store {
            let path = store
                .lookup_share(name, user_id)
                .map_err(|e| {
                    error!("{}", e);
                    response::internal_server_error()
                })?
                .ok_or_else(response::not_found)?;
            Ok(path)
        } else if name == "public" {
            Ok(root)
        } else {
            Err(response::not_found())
        }
    }

    fn get_shares(
        store: &Option<SqliteStore>,
        user_id: Option<i32>,
    ) -> Result<Vec<Share>, Response> {
        if let Some(store) = store {
            let shares = store
                .get_share_names(user_id)
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

    fn index(&self) -> BoxedFuture<Response, Error> {
        Box::new(future::ok(response::found("/browse/")))
    }

    fn favicon(&self) -> BoxedFuture<Response, Error> {
        Box::new(future::ok(response::not_found()))
    }

    fn login(&self, parts: Parts, body: Body) -> BoxedFuture<Response, Error> {
        if parts.method == Method::GET {
            self.login_page()
        } else {
            let store = self.store.clone();
            let fut = {
                let redirect = form_urlencoded::parse(parts.uri.query().unwrap_or("").as_bytes())
                    .filter_map(|p| {
                        if p.0 == "redirect" {
                            Some(p.1.into_owned())
                        } else {
                            None
                        }
                    })
                    .next();
                LoginForm::from_body(body)
                    .and_then(|form| Self::login_action(store, redirect, &form.user, &form.pass))
            };
            Box::new(fut)
        }
    }

    fn browse_or_archive(&self, parts: Parts, body: Body) -> BoxedFuture<Response, Error> {
        let root = self.root.clone();
        let store = self.store.clone();
        let fut = {
            let authentication = Self::get_authentication(&store, &parts);
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
                    let share_name = pb
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
                    let (user_id, user_name) = match authentication {
                        Authentication::User(user_id, name) => {
                            info!(
                                "{} {} /browse/{}/{}",
                                name,
                                parts.method,
                                share_name,
                                path.display()
                            );
                            (Some(user_id), Some(name))
                        }
                        Authentication::Error(_) => {
                            info!(
                                "anonymous {} /browse/{}/{}",
                                parts.method,
                                share_name,
                                path.display()
                            );
                            (None, None)
                        }
                    };

                    match Self::lookup_share(root, &store, &share_name, user_id) {
                        Ok(share_path) => {
                            if parts.method == Method::GET {
                                let request = request_from_parts(&parts);
                                RustyShare::browse(share_name, share_path, path, request, user_name)
                            } else {
                                let fut = files_from_body(body).and_then(move |files| {
                                    RustyShare::archive(share_path, path, files)
                                });
                                Box::new(fut)
                            }
                        }
                        Err(res) => Box::new(future::ok(res)),
                    }
                }
                Err(e) => {
                    error!("{}", e);
                    Box::new(future::ok(response::bad_request()))
                }
            }
        };
        Box::new(fut)
    }

    fn login_page(&self) -> BoxedFuture<Response, Error> {
        Box::new(if self.store.is_some() {
            future::ok(page::login(None))
        } else {
            future::ok(response::not_found())
        })
    }

    fn login_action(
        store: Option<SqliteStore>,
        redirect: Option<String>,
        user: &str,
        pass: &str,
    ) -> BoxedFuture<Response, Error> {
        if let Some(store) = store {
            let user = user.to_string();
            let pass = pass.to_string();
            let redirect = redirect.unwrap_or_else(|| String::from("/browse/"));
            let user_ = user.clone();
            let fut = authenticate(store, user, pass).map(move |session| {
                if let Some(session_id) = session {
                    info!("Authenticating {}: success", user_);
                    response::login_ok(hex::encode(&session_id), &redirect)
                } else {
                    info!("Authenticating {}: failed", user_);
                    page::login(Some(
                        "Login failed. Please contact the site owner to reset your password.",
                    ))
                }
            });
            Box::new(fut)
        } else {
            Box::new(future::ok(response::not_found()))
        }
    }

    fn browse_shares(&self, parts: Parts) -> BoxedFuture<Response, Error> {
        let store = self.store.clone();
        let fut = BlockingFuture::new(move || {
            let authentication = Self::get_authentication(&store, &parts);
            match authentication {
                Authentication::User(user_id, name) => {
                    info!("{} GET /browse/", name);
                    match Self::get_shares(&store, Some(user_id)) {
                        Ok(shares) => page::shares(&shares, Some(name)),
                        Err(response) => response,
                    }
                }
                Authentication::Error(_) => {
                    info!("anonymous GET /browse/");
                    match Self::get_shares(&store, None) {
                        Ok(shares) => page::shares(&shares, None),
                        Err(response) => response,
                    }
                }
            }
        })
        .map_err(|_| Error::StreamCancelled); // FIXME: !
        Box::new(fut)
    }

    fn get_authentication(store: &Option<SqliteStore>, parts: &Parts) -> Authentication {
        Authentication::extract(store, &parts.uri, parts.headers.typed_get::<Cookie>())
    }

    fn browse(
        share_name: String,
        share: PathBuf,
        path: PathBuf,
        request: Request<()>,
        user_name: Option<String>,
    ) -> BoxedFuture<Response, Error> {
        let disk_path = share.join(&path);
        let uri_path = request.uri().path().to_string();

        let fut = tokio_fs::metadata(disk_path.clone()).then(|metadata| match metadata {
            Ok(metadata) => {
                if metadata.is_dir() {
                    if !uri_path.ends_with('/') {
                        Box::new(future::ok(response::found(&(uri_path + "/"))))
                    } else {
                        let fut = BlockingFuture::new(move || {
                            render_index(&share_name, &path, &disk_path, user_name)
                        })
                        .map_err(|_| Error::StreamCancelled); // FIXME: !
                        Box::new(fut) as BoxedFuture<Response, Error>
                    }
                } else {
                    let mut headers = HeaderMap::new();
                    if let Some(mime) = mime_guess::from_path(&disk_path).first_raw() {
                        headers.insert(CONTENT_TYPE, HeaderValue::from_static(mime));
                    }
                    let fut = BlockingFutureTry::new(move || {
                        File::open(&disk_path)
                            .and_then(|file| ChunkedReadFile::new(file, None, headers))
                            .map_err(|e| Error::from_io(e, disk_path))
                    })
                    .map(move |crf| http_serve::serve(crf, &request));

                    Box::new(fut)
                }
            }
            Err(e) => {
                error!("{}", Error::from_io(e, disk_path));
                Box::new(future::ok(response::not_found()))
            }
        });
        Box::new(fut)
    }

    fn archive(share: PathBuf, path: PathBuf, files: Vec<String>) -> BoxedFuture<Response, Error> {
        let disk_path = share.join(&path);
        let fut = BlockingFutureTry::new(move || {
            let mut files = files.iter().map(PathBuf::from).collect::<Vec<_>>();
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
        });
        Box::new(fut)
    }

    pub fn handle_request(&self, req: Request<Body>) -> BoxedFuture<Response, Error> {
        let (parts, body) = req.into_parts();
        match (&parts.method, parts.uri.path()) {
            (&Method::GET, "/") => self.index(),
            (&Method::GET, "/login") | (&Method::POST, "/login") => self.login(parts, body),
            (&Method::GET, "/favicon.ico") => self.favicon(),
            (&Method::GET, "/browse/") => self.browse_shares(parts),
            (&Method::GET, path) | (&Method::POST, path) if path.starts_with("/browse/") => {
                self.browse_or_archive(parts, body)
            }
            _ => Box::new(future::ok(response::not_found())),
        }
    }
}

fn run() -> Result<(), Error> {
    let options = Options::from_args();

    let store: Option<SqliteStore> = options.db.as_ref().map(|db| {
        let should_initialize = !Path::new(&db).exists();
        let store = SqliteStore::new(db);

        if should_initialize {
            info!("Initializing database");
            store
                .initialize_database()
                .expect("unable to create database");
        }

        store
    });

    if let Some(store) = &store {
        match options.command {
            Some(Command::Register { ref user, ref pass }) => {
                register_user(store, &user, &pass)?;
                return Ok(());
            }
            Some(Command::ResetPassword { ref user, ref pass }) => {
                reset_password(store, &user, &pass)?;
                return Ok(());
            }
            Some(Command::CreateShare { ref name, ref path }) => {
                create_share(store, &name, &path)?;
                return Ok(());
            }
            None => {}
        }
    };

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
        store,
    };

    let rusty_share = Arc::new(rusty_share);

    let new_svc = move || {
        let rusty_share = Arc::clone(&rusty_share);
        service_fn(move |req: Request<Body>| rusty_share.handle_request(req))
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
    let percent_decoded = Cow::from(percent_encoding::percent_decode_str(s));
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
    path.to_string_lossy().starts_with('.')
}

fn render_index(
    share_name: &str,
    relative_path: &Path,
    path: &Path,
    user_name: Option<String>,
) -> Response {
    let enumerate_start = Instant::now();
    match get_dir_entries(&path) {
        Ok(entries) => {
            let render_start = Instant::now();
            let enumerate_time = render_start - enumerate_start;
            let rendered = page::index(share_name, &relative_path, &entries, user_name);
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

pub fn register_user(store: &SqliteStore, name: &str, password: &str) -> Result<i32, Error> {
    let hash = scrypt_simple::scrypt_simple(password, 15, 8, 1)?;
    let user_id = store.insert_user(name, &hash)?;
    Ok(user_id)
}

pub fn reset_password(store: &SqliteStore, name: &str, password: &str) -> Result<(), Error> {
    let hash = scrypt_simple::scrypt_simple(password, 15, 8, 1)?;
    store.update_password_by_name(name, &hash)?;
    Ok(())
}

pub fn create_share(store: &SqliteStore, name: &str, path: &str) -> Result<(), Error> {
    store.create_share(name, &path)?;
    Ok(())
}

pub fn authenticate(
    store: SqliteStore,
    name: String,
    password: String,
) -> impl Future<Item = Option<[u8; 16]>, Error = Error> {
    BlockingFutureTry::new(move || {
        let user = store
            .find_user(&name)?
            .and_then(|user| {
                scrypt_simple::scrypt_check(&password, &user.password)
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
    })
}
