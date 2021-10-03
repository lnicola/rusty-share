use std::sync::Arc;

use crate::db::SqliteStore;
use crate::response;
use crate::Response;
use crate::RustyShare;
use async_trait::async_trait;
use axum::body::Empty;
use axum::body::HttpBody;
use axum::extract::FromRequest;
use axum::extract::RequestParts;
use axum::response::IntoResponse;
use bytes::Bytes;
use headers::Cookie;
use headers::HeaderMapExt;
use http::StatusCode;
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

pub enum AuthenticationRejection {
    MissingExtensions,
    MissingHeaders,
    MissingDb,
    InternalError,
}

impl IntoResponse for AuthenticationRejection {
    type Body = Empty<Bytes>;
    type BodyError = <Self::Body as HttpBody>::Error;

    fn into_response(self) -> http::Response<Self::Body> {
        match self {
            AuthenticationRejection::MissingExtensions
            | AuthenticationRejection::MissingHeaders
            | AuthenticationRejection::MissingDb
            | AuthenticationRejection::InternalError => hyper::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Empty::new())
                .unwrap(),
        }
    }
}

#[async_trait]
impl<B: Send> FromRequest<B> for Authentication {
    type Rejection = AuthenticationRejection;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        // TODO: block or block_in_place
        let rusty_share = req
            .extensions()
            .ok_or(AuthenticationRejection::MissingExtensions)?
            .get::<Arc<RustyShare>>()
            .ok_or(AuthenticationRejection::MissingDb)?;
        let store = &rusty_share.store;
        let cookie = req
            .headers()
            .ok_or(AuthenticationRejection::MissingHeaders)?
            .typed_get::<Cookie>();
        let authentication = match check_session(store, req.uri(), cookie) {
            Ok((user_id, name)) => Authentication::User(user_id, name),
            Err(response) => Authentication::Error(response),
        };
        Ok(authentication)
    }
}
