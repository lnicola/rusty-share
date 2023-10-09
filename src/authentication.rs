use std::convert::Infallible;
use std::sync::Arc;

use crate::db::SqliteStore;
use crate::response;
use crate::RustyShare;
use async_trait::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::response::Response;
use headers::{Cookie, HeaderMapExt};
use http::request::Parts;
use http::Uri;

pub enum Authentication {
    User(i32, String),
    Error(Response),
}

fn check_session(
    store: &Option<SqliteStore>,
    uri: &Uri,
    cookie: Option<Cookie>,
) -> Result<(i32, String), Response> {
    let r = if let Some(store) = store {
        let redirect = || response::login_redirect(uri, false);
        let cookie = cookie.ok_or_else(redirect)?;
        let session_id = cookie.get("sid").ok_or_else(redirect)?;
        let session_id = hex::decode(session_id).map_err(|e| {
            tracing::error!("{}", e);
            redirect()
        })?;
        store
            .lookup_session(&session_id)
            .map_err(|e| {
                tracing::error!("{}", e);
                response::internal_server_error()
            })?
            .ok_or_else(redirect)?
    } else {
        (0, String::new())
    };
    Ok(r)
}

#[async_trait]
impl<S> FromRequestParts<S> for Authentication
where
    Arc<RustyShare>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let rusty_share = Arc::<RustyShare>::from_ref(state);
        let store = &rusty_share.store;
        let cookie = parts.headers.typed_get::<Cookie>();
        let authentication = match check_session(store, &parts.uri, cookie) {
            Ok((user_id, name)) => Authentication::User(user_id, name),
            Err(response) => Authentication::Error(response),
        };
        Ok(authentication)
    }
}
