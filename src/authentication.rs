use std::pin::Pin;
use std::sync::Arc;

use crate::db::SqliteStore;
use crate::response;
use crate::Response;
use crate::RustyShare;
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
use std::future::Future;

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
    Extensions,
    Headers,
    Db,
}

impl IntoResponse for AuthenticationRejection {
    type Body = Empty<Bytes>;
    type BodyError = <Self::Body as HttpBody>::Error;

    fn into_response(self) -> http::Response<Self::Body> {
        match self {
            AuthenticationRejection::Extensions
            | AuthenticationRejection::Headers
            | AuthenticationRejection::Db => hyper::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Empty::new())
                .unwrap(),
        }
    }
}

impl<B: Send> FromRequest<B> for Authentication {
    type Rejection = AuthenticationRejection;
    fn from_request<'a, 'f>(
        req: &'a mut RequestParts<B>,
    ) -> Pin<Box<dyn Future<Output = Result<Self, Self::Rejection>> + Send + 'f>>
    where
        'a: 'f,
    {
        Box::pin(async move {
            let rusty_share = req
                .extensions()
                .ok_or(AuthenticationRejection::Extensions)?
                .get::<Arc<RustyShare>>()
                .ok_or(AuthenticationRejection::Db)?;
            let store = &rusty_share.store;
            let cookie = req
                .headers()
                .ok_or(AuthenticationRejection::Headers)?
                .typed_get::<Cookie>();
            let authentication = match check_session(store, req.uri(), cookie) {
                Ok((user_id, name)) => Authentication::User(user_id, name),
                Err(response) => Authentication::Error(response),
            };
            Ok(authentication)
        })
    }
}
