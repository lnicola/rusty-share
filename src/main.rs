use axum::extract::{self, BodyStream, Form, OriginalUri, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures_util::stream::StreamExt;
use http::header::CONTENT_TYPE;
use http::{HeaderMap, HeaderValue, Request, Uri};
use hyper::body::HttpBody;
use hyper::service::Service;
use hyper::{Body, Server};
use os_str_bytes::OsStrBytes;
use rand_core::{OsRng, RngCore};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::slice::ParallelSliceMut;
use scrypt::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use scrypt::Scrypt;
use serde::Deserialize;
use std::ffi::OsStr;
use std::fs::{self, DirEntry};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str;
use std::sync::Arc;
use std::time::Instant;
use tar::Builder;
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeFile;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;
use walkdir::WalkDir;

use archive::Archive;
use authentication::Authentication;
use db::models::{AccessLevel, NewUser, Share, User};
use db::SqliteStore;
use error::Error;
use forms::{Files, LoginForm, Redirect};
use options::{Args, Command};
use pipe::Pipe;
use share_entry::ShareEntry;

mod archive;
mod authentication;
mod db;
mod error;
mod forms;
mod options;
mod page;
mod pipe;
mod response;
mod share_entry;

struct RustyShare {
    root: PathBuf,
    store: Option<SqliteStore>,
}

#[derive(Deserialize)]
struct RequestPath {
    share: String,
    #[serde(default)]
    path: PathBuf,
}

fn get_archive(archive: Archive) -> Body {
    let (tx, mut rx) = mpsc::channel(1);
    let pipe = Pipe::new(tx);
    let mut builder = Builder::new(pipe);
    let f = task::spawn_blocking(move || {
        for entry in archive.entries() {
            if let Err(e) = entry.write_to(&mut builder) {
                tracing::error!("{}", e);
            }
        }
        builder.finish()
    });
    tokio::spawn(f);

    let stream = async_stream::stream! {
        while let Some(chunk) = rx.recv().await {
            yield Ok::<_, Error>(chunk);
        }
    };
    Body::wrap_stream(stream)
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

impl RustyShare {
    async fn lookup_share(
        root: &Path,
        store: &Option<SqliteStore>,
        name: &str,
        user_id: Option<i32>,
    ) -> Result<Option<Share>, Error> {
        task::block_in_place(move || {
            if let Some(store) = store {
                let path = store.lookup_share(name, user_id).map_err(|e| {
                    tracing::error!("{}", e);
                    e
                })?;
                Ok(path)
            } else if name == "public" {
                Ok(Some(Share {
                    id: 0,
                    name: String::from("public"),
                    path: root.to_path_buf(),
                    access_level: AccessLevel::Public,
                    upload_allowed: false,
                }))
            } else {
                Err(Error::ShareNotFound)
            }
        })
    }

    async fn get_shares(
        store: &Option<SqliteStore>,
        user_id: Option<i32>,
    ) -> Result<Vec<Share>, Error> {
        if let Some(store) = store {
            task::block_in_place(move || {
                let shares = store.get_accessible_shares(user_id).map_err(|e| {
                    tracing::error!("{}", e);
                    e
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

    pub async fn index(&self) -> Result<Response, Error> {
        Ok(response::found("/browse/"))
    }

    async fn favicon(&self) -> Result<Response, Error> {
        Ok(response::not_found())
    }

    async fn browse_(
        &self,
        share: &str,
        local_path: PathBuf,
        original_uri: Uri,
        authentication: Authentication,
        request: Request<Body>,
    ) -> Result<Response, Error> {
        let (user_id, user_name) = match authentication {
            Authentication::User(user_id, name) => {
                tracing::info!("{} {}", name, original_uri);
                (Some(user_id), Some(name))
            }
            Authentication::Error(_) => {
                tracing::info!("anonymous {}", original_uri);
                (None, None)
            }
        };

        let r = Self::lookup_share(&self.root, &self.store, share, user_id).await?;
        match r {
            Some(share) => RustyShare::browse(share, local_path, request, user_name).await,
            None => Ok(response::login_redirect(&original_uri, false)),
        }
    }

    async fn archive_(
        &self,
        share: &str,
        local_path: PathBuf,
        original_uri: Uri,
        files: Form<Files>,
        authentication: Authentication,
    ) -> Result<Response, Error> {
        let user_id = match authentication {
            Authentication::User(user_id, name) => {
                tracing::info!("{} {}", name, original_uri);
                Some(user_id)
            }
            Authentication::Error(_) => {
                tracing::info!("anonymous {}", original_uri);
                None
            }
        };

        let r = Self::lookup_share(&self.root, &self.store, share, user_id).await?;
        match r {
            Some(share) => {
                let files = files
                    .0
                    .s
                    .into_iter()
                    .filter(|p| p.0 == "s")
                    .map(|(_, f)| PathBuf::from(f))
                    .collect::<Vec<_>>();
                RustyShare::archive(share.path, local_path, files).await
            }
            None => Ok(response::login_redirect(&original_uri, false)),
        }
    }

    async fn upload(
        &self,
        share: &str,
        local_path: &Path,
        original_uri: Uri,
        authentication: Authentication,
        body_stream: BodyStream,
    ) -> Result<Response, Error> {
        let (user_id, _) = match authentication {
            Authentication::User(user_id, name) => {
                tracing::info!("{} {}", name, original_uri);
                (Some(user_id), Some(name))
            }
            Authentication::Error(_) => {
                tracing::info!("anonymous {}", original_uri);
                (None, None)
            }
        };

        match Self::lookup_share(&self.root, &self.store, share, user_id).await? {
            Some(share) if share.upload_allowed => {
                RustyShare::do_upload(&share.path.join(local_path), body_stream)
                    .await
                    .map_err(|e| {
                        tracing::error!("{}", e);
                        e
                    })?;
                Ok(response::no_content())
            }
            None => Ok(response::login_redirect(&original_uri, false)),
            _ => Ok(response::forbidden()),
        }
    }

    async fn login_page(&self) -> Result<Response, Error> {
        if self.store.is_some() {
            Ok(page::login(None).map_err(|e| {
                tracing::error!("{}", e);
                e
            })?)
        } else {
            Err(Error::DatabaseNotAvailable)
        }
    }

    async fn login_action(
        store: Option<&SqliteStore>,
        redirect: Option<String>,
        user: &str,
        pass: &str,
    ) -> Result<Response, Error> {
        if let Some(store) = store {
            let redirect = redirect.unwrap_or_else(|| String::from("/browse/"));
            let session = authenticate(store, user, pass).await?;
            let response = if let Some(session_id) = session {
                tracing::info!("Authenticating {}: success", user);
                response::login_ok(hex::encode(session_id), &redirect)
            } else {
                tracing::info!("Authenticating {}: failed", user);
                page::login(Some(
                    "Login failed. Please contact the site owner to reset your password.",
                ))
                .map_err(|e| {
                    tracing::error!("{}", e);
                    e
                })?
            };
            Ok(response)
        } else {
            Err(Error::DatabaseNotAvailable)
        }
    }

    async fn browse_shares(&self, authentication: Authentication) -> Result<Response, Error> {
        let response = match authentication {
            Authentication::User(user_id, name) => {
                tracing::info!("{} GET /browse/", name);
                let shares = Self::get_shares(&self.store, Some(user_id)).await?;
                page::shares(shares, Some(name)).map_err(|e| {
                    tracing::error!("{}", e);
                    e
                })?
            }
            Authentication::Error(_) => {
                tracing::info!("anonymous GET /browse/");
                let shares = Self::get_shares(&self.store, None).await?;
                page::shares(shares, None).map_err(|e| {
                    tracing::error!("{}", e);
                    e
                })?
            }
        };
        Ok(response)
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
                        response::found(&format!("/browse/{}/{}/", share.name, path.display()))
                    } else {
                        task::block_in_place(move || {
                            render_index(
                                &share.name,
                                &path,
                                &disk_path,
                                share.upload_allowed,
                                user_name,
                            )
                        })?
                    }
                } else {
                    let mut headers = HeaderMap::new();
                    if let Some(mime) = mime_guess::from_path(&disk_path).first_raw() {
                        headers.insert(CONTENT_TYPE, HeaderValue::from_static(mime));
                    }

                    let response = ServeFile::new(&disk_path).call(request).await?;
                    Response::builder()
                        .body(response.boxed_unsync())
                        .unwrap()
                        .map_err(Error::from)
                        .into_response()
                }
            }
            Err(e) => {
                let e = Error::from_io(e, disk_path);
                tracing::error!("{}", e);
                response::not_found()
            }
        };
        Ok(response)
    }

    async fn do_upload(path: &Path, mut body_stream: BodyStream) -> Result<(), Error> {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await?;
        while let Some(bytes) = body_stream.next().await {
            let bytes = bytes?;
            file.write_all(&bytes).await?;
        }
        Ok(())
    }

    async fn archive(
        share: PathBuf,
        path: PathBuf,
        mut files: Vec<PathBuf>,
    ) -> Result<Response, Error> {
        let disk_path = share.join(path);
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
                    tracing::info!("{}", file.display());
                    let entries = WalkDir::new(disk_path.join(file))
                        .into_iter()
                        .filter_entry(|e| !is_hidden(e.file_name()));
                    for entry in entries {
                        if let Err(e) = entry
                            .map_err(Error::from)
                            .and_then(|entry| archive.add_entry(&disk_path, entry))
                        {
                            tracing::error!("{}", e);
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

fn get_store(path: &Path) -> SqliteStore {
    let should_initialize = !Path::new(&path).exists();
    let store = SqliteStore::new(path).unwrap();

    if should_initialize {
        tracing::info!("Initializing database");
        store
            .initialize_database()
            .expect("unable to create database");
    }

    store
}

async fn index(state: State<Arc<RustyShare>>) -> impl IntoResponse {
    state.index().await
}

async fn login_page(state: State<Arc<RustyShare>>) -> impl IntoResponse {
    state.login_page().await
}

async fn login_post(
    state: State<Arc<RustyShare>>,
    redirect: Option<Query<Redirect>>,
    login_form: Form<LoginForm>,
) -> impl IntoResponse {
    RustyShare::login_action(
        state.store.as_ref(),
        redirect.map(|r| r.0.redirect),
        &login_form.user,
        &login_form.pass,
    )
    .await
}

async fn favicon(state: State<Arc<RustyShare>>) -> impl IntoResponse {
    state.favicon().await
}

async fn share_browse(
    extract::Path(request_path): extract::Path<RequestPath>,
    original_uri: OriginalUri,
    authentication: Authentication,
    state: State<Arc<RustyShare>>,
    req: Request<Body>,
) -> impl IntoResponse {
    tracing::trace!(
        share = %request_path.share,
        path = %request_path.path.display(),
        original_uri = %original_uri.0
    );
    state
        .browse_(
            &request_path.share,
            request_path.path,
            original_uri.0,
            authentication,
            req,
        )
        .await
}

async fn share_archive(
    extract::Path(request_path): extract::Path<RequestPath>,
    original_uri: OriginalUri,
    authentication: Authentication,
    state: State<Arc<RustyShare>>,
    files: Form<Files>,
) -> impl IntoResponse {
    state
        .archive_(
            &request_path.share,
            request_path.path,
            original_uri.0,
            files,
            authentication,
        )
        .await
}

async fn share_index(
    authentication: Authentication,
    state: State<Arc<RustyShare>>,
) -> impl IntoResponse {
    state.browse_shares(authentication).await
}

async fn share_redirect(
    extract::Path(request_path): extract::Path<RequestPath>,
    authentication: Authentication,
    state: State<Arc<RustyShare>>,
) -> impl IntoResponse {
    if request_path.share.is_empty() {
        state.browse_shares(authentication).await.unwrap()
    } else {
        response::found(&format!("{}/", request_path.share))
    }
}

async fn upload(
    request_path: extract::Path<RequestPath>,
    original_uri: OriginalUri,
    authentication: Authentication,
    state: State<Arc<RustyShare>>,
    body_stream: BodyStream,
) -> impl IntoResponse {
    state
        .upload(
            &request_path.share,
            request_path.path.as_path(),
            original_uri.0,
            authentication,
            body_stream,
        )
        .await
        .unwrap()
}

async fn run() -> Result<(), Error> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "rusty_share=info,tower_http=info")
    }
    tracing_subscriber::fmt::init();

    let args = Args::parse().unwrap();

    match args.command {
        Command::Register {
            user,
            pass,
            db_path,
        } => {
            let store = get_store(&db_path);
            register_user(&store, user, &pass)?;
            Ok(())
        }
        Command::ResetPassword {
            user,
            pass,
            db_path,
        } => {
            let store = get_store(&db_path);
            reset_password(&store, &user, &pass)?;
            Ok(())
        }
        Command::CreateShare {
            name,
            path,
            db_path,
        } => {
            let store = get_store(&db_path);
            let share = db::models::NewShare {
                name,
                path,
                access_level: AccessLevel::Restricted,
                upload_allowed: false,
            };
            store.create_share(share)?;
            Ok(())
        }
        Command::Start {
            root,
            db_path,
            address,
            port,
        } => {
            let addr = SocketAddr::new(
                address
                    .parse::<IpAddr>()
                    .map_err(|e| Error::from_addr_parse(e, address.clone()))?,
                port,
            );
            tracing::info!("Listening on http://{}", addr);

            let store = db_path.as_ref().map(|db_path| get_store(db_path));
            let rusty_share = RustyShare { root, store };
            let rusty_share = Arc::new(rusty_share);

            let state = Arc::clone(&rusty_share);

            let app = Router::new()
                .route("/", get(index))
                .route("/login", get(login_page).post(login_post))
                .route("/favicon.ico", get(favicon))
                .route("/browse/", get(share_index))
                .route(
                    "/browse/:share",
                    get(share_redirect).post(share_redirect).put(upload),
                )
                .route(
                    "/browse/:share/",
                    get(share_browse)
                        .head(share_browse)
                        .post(share_archive)
                        .put(upload),
                )
                .route(
                    "/browse/:share/*path",
                    get(share_browse)
                        .head(share_browse)
                        .post(share_archive)
                        .put(upload),
                )
                .with_state(state)
                .layer(CookieManagerLayer::new())
                .layer(
                    TraceLayer::new_for_http()
                        .on_response(DefaultOnResponse::new().level(Level::INFO)),
                );

            let listener = std::net::TcpListener::bind(addr)?;

            let server = Server::from_tcp(listener)?
                .tcp_nodelay(true)
                .serve(app.into_make_service());
            Ok(server.await?)
        }
        Command::Help => Ok(()),
    }
}

fn main() {
    unsafe {
        rusqlite::bypass_sqlite_version_check();
    }
    let rt = Runtime::new().expect("cannot start runtime");
    rt.block_on(async move { run().await }).unwrap();
}

fn dir_entries(path: &Path) -> Result<impl Iterator<Item = DirEntry>, Error> {
    Ok(fs::read_dir(path)
        .map_err(|e| Error::from_io(e, path.to_path_buf()))?
        .filter_map(|file| {
            file.map_err(|e| {
                tracing::error!("{}", e);
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
                tracing::error!("{}", e);
                None
            }
        })
        .collect::<Vec<_>>();

    entries.par_sort_unstable_by(|e1, e2| (e2.is_dir(), e2.date()).cmp(&(e1.is_dir(), e1.date())));

    Ok(entries)
}

pub fn is_hidden(path: &OsStr) -> bool {
    matches!(path.to_raw_bytes().iter().next(), Some(b'.'))
}

fn render_index(
    share_name: &str,
    relative_path: &Path,
    path: &Path,
    upload_allowed: bool,
    user_name: Option<String>,
) -> Result<Response, Error> {
    let enumerate_start = Instant::now();
    let entries = get_dir_entries(path).map_err(|e| {
        tracing::error!("{}", e);
        e
    })?;
    let render_start = Instant::now();
    let enumerate_time = render_start - enumerate_start;
    let rendered = page::index(
        share_name,
        relative_path,
        &entries,
        upload_allowed,
        user_name,
    )
    .map_err(|e| {
        tracing::error!("{}", e);
        e
    })?;
    let render_time = Instant::now() - render_start;
    tracing::info!(
        "enumerate: {} ms, render: {} ms",
        enumerate_time.as_millis(),
        render_time.as_millis()
    );
    Ok(rendered)
}

pub fn register_user(store: &SqliteStore, name: String, password: &str) -> Result<User, Error> {
    let salt = SaltString::generate(OsRng);
    let hash = Scrypt.hash_password(password.as_bytes(), salt.as_str())?;
    let user = NewUser {
        name,
        password: hash.to_string(),
    };
    let user = store.create_user(user)?;
    Ok(user)
}

pub fn reset_password(store: &SqliteStore, name: &str, password: &str) -> Result<(), Error> {
    let salt = SaltString::generate(OsRng);
    let hash = Scrypt.hash_password(password.as_bytes(), salt.as_str())?;
    store.update_password_by_name(name, &hash.to_string())?;
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
                PasswordHash::new(&user.password.clone())
                    .ok()
                    .and_then(|hash| {
                        Scrypt
                            .verify_password(password.as_bytes(), &hash)
                            .map(|_| user)
                            .map_err(|e| {
                                tracing::error!(
                                    "Password verification failed for user {}: {}",
                                    name,
                                    e
                                )
                            })
                            .ok()
                    })
            })
            .and_then(|user| {
                let mut session_id = [0; 16];
                if let Err(e) = OsRng.try_fill_bytes(&mut session_id) {
                    tracing::error!("Error generating session id for user id {}: {}", user.id, e);
                    return None;
                }
                if let Err(e) = store.create_session(&session_id, user.id) {
                    tracing::error!("Error saving session for user id {}: {}", user.id, e);
                }

                Some(session_id)
            });

        Ok(user)
    })
}
