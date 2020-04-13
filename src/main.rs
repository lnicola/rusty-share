use archive::Archive;
use authentication::Authentication;
use error::Error;
use futures::stream::StreamExt;
use headers::{Cookie, HeaderMapExt};
use hex;
use http::header::CONTENT_TYPE;
use http::{HeaderMap, HeaderValue, Method, Request};
use http_serve::{self, ChunkedReadFile};
use hyper::{body, service};
use hyper::{Body, Server};
use log::{error, info};
use mime_guess;
use options::{Command, Options};
use os_str_bytes::{OsStrBytes, OsStringBytes};
use pipe::Pipe;
use pretty_env_logger;
use rand::{self, Rng};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::slice::ParallelSliceMut;
use share_entry::ShareEntry;
use std::borrow::Cow;
use std::ffi::OsStr;
use std::fs::{self, DirEntry};
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::str;
use std::sync::Arc;
use std::time::Instant;
use structopt::StructOpt;
use tar::Builder;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::task;
use url::form_urlencoded;
use walkdir::WalkDir;

use db::models::{AccessLevel, NewUser, Share, User};
use db::SqliteStore;

mod archive;
mod authentication;
mod db;
mod error;
mod options;
mod page;
mod pipe;
mod response;
mod scrypt_simple;
mod share_entry;

type Response = http::Response<Body>;

struct RustyShare {
    root: PathBuf,
    store: Option<SqliteStore>,
}

fn get_archive(archive: Archive) -> Body {
    let (tx, rx) = mpsc::channel(1);
    let pipe = Pipe::new(tx);
    let mut builder = Builder::new(pipe);
    let f = task::spawn_blocking(move || {
        for entry in archive.entries() {
            if let Err(e) = entry.write_to(&mut builder) {
                error!("{}", e);
            }
        }
        builder.finish()
    });
    tokio::spawn(f);

    let rx = rx.map(|chunk| Ok::<_, Error>(chunk));
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
    pub async fn from_body(body: Body) -> Result<Self, Error> {
        let bytes = body::to_bytes(body).await?;

        let mut user = String::new();
        let mut pass = String::new();
        for p in form_urlencoded::parse(bytes.as_ref()) {
            match p.0.as_ref() {
                "user" => user = p.1.into_owned(),
                "pass" => pass = p.1.into_owned(),
                _ => {}
            }
        }
        Ok(Self { user, pass })
    }
}

struct RegisterForm {
    user: String,
    pass: String,
    confirm_pass: String,
}

impl RegisterForm {
    pub async fn from_body(body: Body) -> Result<Self, Error> {
        let bytes = body::to_bytes(body).await?;

        let mut user = String::new();
        let mut pass = String::new();
        let mut confirm_pass = String::new();

        for p in form_urlencoded::parse(bytes.as_ref()) {
            match p.0.as_ref() {
                "user" => user = p.1.into_owned(),
                "pass" => pass = p.1.into_owned(),
                "confirm_pass" => confirm_pass = p.1.into_owned(),
                _ => {}
            }
        }
        Ok(Self {
            user,
            pass,
            confirm_pass,
        })
    }
}

async fn files_from_body(body: Body) -> Result<Vec<PathBuf>, Error> {
    let bytes = body::to_bytes(body).await?;
    let files = form_urlencoded::parse(bytes.as_ref())
        .filter_map(|p| {
            if p.0 == "s" {
                let percent_decoded = Cow::from(percent_encoding::percent_decode_str(p.1.as_ref()));
                PathBuf::from_bytes(percent_decoded.into_owned())
                    .map_err(|e| error!("cannot decode {}: {}", p.1, e))
                    .ok()
            } else {
                None
            }
        })
        .collect();
    Ok(files)
}

impl RustyShare {
    async fn lookup_share(
        root: &Path,
        store: &Option<SqliteStore>,
        name: &str,
        user_id: Option<i32>,
    ) -> Result<Share, Response> {
        task::block_in_place(move || {
            if let Some(store) = store {
                let path = store
                    .lookup_share(&name, user_id)
                    .map_err(|e| {
                        error!("{}", e);
                        response::internal_server_error()
                    })?
                    .ok_or_else(response::not_found)?;
                Ok(path)
            } else if name == "public" {
                Ok(Share {
                    id: 0,
                    name: String::from("public"),
                    path: root.to_path_buf(),
                    access_level: AccessLevel::Public,
                    upload_allowed: false,
                })
            } else {
                Err(response::not_found())
            }
        })
    }

    async fn get_shares(
        store: &Option<SqliteStore>,
        user_id: Option<i32>,
    ) -> Result<Vec<Share>, Response> {
        if let Some(store) = store {
            task::block_in_place(move || {
                let shares = store.get_accessible_shares(user_id).map_err(|e| {
                    error!("{}", e);
                    response::internal_server_error()
                })?;
                Ok(shares)
            })
        } else {
            Ok(vec![Share {
                id: 0,
                name: String::from("public"),
                path: PathBuf::new(),
                access_level: AccessLevel::Public,
                upload_allowed: false,
            }])
        }
    }

    async fn index(&self) -> Result<Response, Error> {
        Ok(response::found("/browse/"))
    }

    async fn favicon(&self) -> Result<Response, Error> {
        Ok(response::not_found())
    }

    async fn login(&self, request: Request<Body>) -> Result<Response, Error> {
        let redirect = form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
            .filter_map(|p| {
                if p.0 == "redirect" {
                    Some(p.1.into_owned())
                } else {
                    None
                }
            })
            .next();
        let form = LoginForm::from_body(request.into_body()).await?;
        Self::login_action(self.store.as_ref(), redirect, &form.user, &form.pass).await
    }

    async fn register(&self, request: Request<Body>) -> Result<Response, Error> {
        let response = if let Some(store) = self.store.as_ref() {
            let method = request.method().clone();
            let form = RegisterForm::from_body(request.into_body()).await?;
            if &form.pass != &form.confirm_pass {
                page::register(Some("Registration failed: passwords don't match."))
            } else {
                let response = match store.users_exist() {
                    Ok(true) => response::not_found(),
                    Ok(false) => {
                        if method == Method::GET {
                            page::register(None)
                        } else {
                            Self::register_action(store, form.user, &form.pass)
                        }
                    }
                    Err(e) => {
                        error!("{}", e);
                        response::internal_server_error()
                    }
                };
                response
            }
        } else {
            response::not_found()
        };
        Ok(response)
    }

    async fn browse_or_archive(&self, request: Request<Body>) -> Result<Response, Error> {
        let authentication = Self::get_authentication(&self.store, &request);
        let pb = decode(request.uri().path())
            .map(|s| {
                s.components()
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
                            request.method(),
                            share_name,
                            path.display()
                        );
                        (Some(user_id), Some(name))
                    }
                    Authentication::Error(_) => {
                        info!(
                            "anonymous {} /browse/{}/{}",
                            request.method(),
                            share_name,
                            path.display()
                        );
                        (None, None)
                    }
                };

                let r = Self::lookup_share(&self.root, &self.store, &share_name, user_id).await;
                match r {
                    Ok(share) => {
                        if request.method() == Method::GET || request.method() == Method::HEAD {
                            RustyShare::browse(share, path, request, user_name).await
                        } else if request.method() == Method::POST {
                            let files = files_from_body(request.into_body()).await?;
                            RustyShare::archive(share.path, path, files).await
                        } else {
                            Ok(response::method_not_allowed())
                        }
                    }
                    Err(res) => Ok(res),
                }
            }
            Err(e) => {
                error!("{}", e);
                Ok(response::bad_request())
            }
        }
    }

    async fn upload(&self, request: Request<Body>) -> Result<Response, Error> {
        let authentication = Self::get_authentication(&self.store, &request);
        let pb = decode(request.uri().path())
            .map(|s| {
                s.components()
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
                let (user_id, _) = match authentication {
                    Authentication::User(user_id, name) => {
                        info!(
                            "{} {} /browse/{}/{}",
                            name,
                            request.method(),
                            share_name,
                            path.display()
                        );
                        (Some(user_id), Some(name))
                    }
                    Authentication::Error(_) => {
                        info!(
                            "anonymous {} /browse/{}/{}",
                            request.method(),
                            share_name,
                            path.display()
                        );
                        (None, None)
                    }
                };

                let r = Self::lookup_share(&self.root, &self.store, &share_name, user_id).await;
                match r {
                    Ok(share) if share.upload_allowed => {
                        match RustyShare::do_upload(&share.path.join(&path), request).await {
                            Ok(_) => Ok(response::no_content()),
                            Err(e) => {
                                error!("{}", e);
                                Ok(response::internal_server_error())
                            }
                        }
                    }
                    Ok(_) => Ok(response::forbidden()),
                    Err(res) => Ok(res),
                }
            }
            Err(e) => {
                error!("{}", e);
                Ok(response::bad_request())
            }
        }
    }

    async fn login_page(&self) -> Result<Response, Error> {
        if self.store.is_some() {
            Ok(page::login(None))
        } else {
            Ok(response::not_found())
        }
    }

    async fn login_action(
        store: Option<&SqliteStore>,
        redirect: Option<String>,
        user: &str,
        pass: &str,
    ) -> Result<Response, Error> {
        let response = if let Some(store) = store {
            let redirect = redirect.unwrap_or_else(|| String::from("/browse/"));
            let session = authenticate(store, user, pass).await?;
            if let Some(session_id) = session {
                info!("Authenticating {}: success", user);
                response::login_ok(hex::encode(&session_id), &redirect)
            } else {
                info!("Authenticating {}: failed", user);
                page::login(Some(
                    "Login failed. Please contact the site owner to reset your password.",
                ))
            }
        } else {
            response::not_found()
        };
        Ok(response)
    }

    fn register_action(store: &SqliteStore, user: String, pass: &str) -> Response {
        match register_user(store, user, pass) {
            Ok(_) => response::register_ok("/login"),
            Err(_) => page::register(Some("Registration failed.")),
        }
    }

    async fn browse_shares(&self, request: Request<Body>) -> Result<Response, Error> {
        let authentication =
            task::block_in_place(move || Self::get_authentication(&self.store, &request));
        let response = match authentication {
            Authentication::User(user_id, name) => {
                info!("{} GET /browse/", name);
                let r = Self::get_shares(&self.store, Some(user_id)).await;
                match r {
                    Ok(shares) => page::shares(shares, Some(name)),
                    Err(response) => response,
                }
            }
            Authentication::Error(_) => {
                info!("anonymous GET /browse/");
                let r = Self::get_shares(&self.store, None).await;
                match r {
                    Ok(shares) => page::shares(shares, None),
                    Err(response) => response,
                }
            }
        };
        Ok(response)
    }

    fn get_authentication(store: &Option<SqliteStore>, request: &Request<Body>) -> Authentication {
        Authentication::extract(
            store,
            request.uri(),
            request.headers().typed_get::<Cookie>(),
        )
    }

    async fn browse(
        share: Share,
        path: PathBuf,
        request: Request<Body>,
        user_name: Option<String>,
    ) -> Result<Response, Error> {
        let disk_path = share.path.join(&path);
        let uri_path = request.uri().path().to_string();

        let metadata = tokio::fs::metadata(&disk_path).await;
        let response = match metadata {
            Ok(metadata) => {
                if metadata.is_dir() {
                    if !uri_path.ends_with('/') {
                        response::found(&(uri_path + "/"))
                    } else {
                        task::block_in_place(move || {
                            render_index(
                                &share.name,
                                &path,
                                &disk_path,
                                share.upload_allowed,
                                user_name,
                            )
                        })
                    }
                } else {
                    let mut headers = HeaderMap::new();
                    if let Some(mime) = mime_guess::from_path(&disk_path).first_raw() {
                        headers.insert(CONTENT_TYPE, HeaderValue::from_static(mime));
                    }
                    let file = tokio::fs::File::open(&disk_path).await?.into_std().await;
                    let crf = ChunkedReadFile::new(file, headers)?;
                    http_serve::serve(crf, &request)
                }
            }
            Err(e) => {
                error!("{}", Error::from_io(e, disk_path));
                response::not_found()
            }
        };
        Ok(response)
    }

    async fn do_upload(path: &Path, request: Request<Body>) -> Result<(), Error> {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await?;
        let mut body = request.into_body();
        while let Some(bytes) = body.next().await {
            file.write_all(bytes?.as_ref()).await?;
        }
        Ok(())
    }

    async fn archive(
        share: PathBuf,
        path: PathBuf,
        mut files: Vec<PathBuf>,
    ) -> Result<Response, Error> {
        let disk_path = share.join(&path);
        task::block_in_place(move || {
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

    pub async fn handle_request(self: Arc<Self>, req: Request<Body>) -> Result<Response, Error> {
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => self.index().await,
            (&Method::GET, "/register") | (&Method::POST, "/register") => self.register(req).await,
            (&Method::GET, "/login") => self.login_page().await,
            (&Method::POST, "/login") => self.login(req).await,
            (&Method::GET, "/favicon.ico") => self.favicon().await,
            (&Method::GET, "/browse/") => self.browse_shares(req).await,
            (&Method::GET, path) | (&Method::HEAD, path) | (&Method::POST, path)
                if path.starts_with("/browse/") =>
            {
                self.browse_or_archive(req).await
            }
            (&Method::PUT, path) if path.starts_with("/browse") => self.upload(req).await,
            _ => Ok(response::not_found()),
        }
    }
}

async fn run() -> Result<(), Error> {
    pretty_env_logger::init();

    let options = Options::from_args();

    let store: Option<SqliteStore> = options.db.as_ref().map(|db| {
        let should_initialize = !Path::new(&db).exists();
        let store = SqliteStore::new(db).unwrap();

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
            Some(Command::Register { user, pass }) => {
                register_user(store, user, &pass)?;
                return Ok(());
            }
            Some(Command::ResetPassword { ref user, ref pass }) => {
                reset_password(store, &user, &pass)?;
                return Ok(());
            }
            Some(Command::CreateShare { name, path }) => {
                let share = db::models::NewShare {
                    name,
                    path,
                    access_level: AccessLevel::Restricted,
                    upload_allowed: false,
                };
                store.create_share(share)?;
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

    let new_svc = service::make_service_fn(move |_| {
        let rusty_share = Arc::clone(&rusty_share);
        futures::future::ok::<_, Error>(service::service_fn(move |req| {
            RustyShare::handle_request(Arc::clone(&rusty_share), req)
        }))
    });

    let listener = std::net::TcpListener::bind(&addr)?;

    let server = Server::from_tcp(listener)?.tcp_nodelay(true).serve(new_svc);
    Ok(server.await?)
}

fn decode(s: &str) -> Result<PathBuf, Error> {
    let percent_decoded = Cow::from(percent_encoding::percent_decode_str(s));
    let os_str = PathBuf::from_bytes(percent_decoded).map_err(|_e| Error::InvalidArgument)?;
    Ok(os_str)
}

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
    let mut rt = tokio::runtime::Builder::new()
        .threaded_scheduler()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move { run().await }).unwrap();
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
    matches!(path.to_bytes().as_ref().iter().next(), Some(b'.'))
}

fn render_index(
    share_name: &str,
    relative_path: &Path,
    path: &Path,
    upload_allowed: bool,
    user_name: Option<String>,
) -> Response {
    let enumerate_start = Instant::now();
    match get_dir_entries(&path) {
        Ok(entries) => {
            let render_start = Instant::now();
            let enumerate_time = render_start - enumerate_start;
            let rendered = page::index(
                share_name,
                &relative_path,
                &entries,
                upload_allowed,
                user_name,
            );
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

pub fn register_user(store: &SqliteStore, name: String, password: &str) -> Result<User, Error> {
    let hash = scrypt_simple::scrypt_simple(password, 15, 8, 1)?;
    let user = NewUser {
        name,
        password: hash,
    };
    let user = store.create_user(user)?;
    Ok(user)
}

pub fn reset_password(store: &SqliteStore, name: &str, password: &str) -> Result<(), Error> {
    let hash = scrypt_simple::scrypt_simple(password, 15, 8, 1)?;
    store.update_password_by_name(name, &hash)?;
    Ok(())
}

pub async fn authenticate(
    store: &SqliteStore,
    name: &str,
    password: &str,
) -> Result<Option<[u8; 16]>, Error> {
    task::block_in_place(move || {
        let user = store
            .find_user(name)?
            .and_then(|user| {
                scrypt_simple::scrypt_check(password, &user.password)
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
