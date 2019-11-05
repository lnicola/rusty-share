use crate::db::Store;
use crate::response;
use crate::Response;
use headers::Cookie;
use http::Uri;
use log::error;

pub enum Authentication {
    User(i32, String),
    Error(Response),
}

fn check_session(
    store: &Option<Store>,
    uri: &Uri,
    cookie: Option<Cookie>,
) -> Result<(i32, String), Response> {
    let r = if let Some(store) = store {
        let redirect = || response::login_redirect(uri, false);
        let cookie = cookie.ok_or_else(redirect)?;
        let session_id = cookie.get("sid").ok_or_else(redirect)?;
        let session_id = hex::decode(session_id).map_err(|e| {
            error!("{}", e);
            redirect()
        })?;
        store
            .lookup_session(&session_id)
            .map_err(|e| {
                error!("{}", e);
                response::internal_server_error()
            })?
            .ok_or_else(redirect)?
    } else {
        (0, String::new())
    };
    Ok(r)
}

impl Authentication {
    pub fn extract(store: &Option<Store>, uri: &Uri, cookie: Option<Cookie>) -> Self {
        match check_session(&store, uri, cookie) {
            Ok((user_id, name)) => Authentication::User(user_id, name),
            Err(response) => Authentication::Error(response),
        }
    }
}
