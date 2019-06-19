use crate::db_store::DbStore;
use crate::response;
use crate::Response;
use headers::Cookie;
use http::Uri;
use log::error;

pub enum Authentication {
    User(String),
    Error(Response),
}

fn check_session(store: &DbStore, uri: &Uri, cookie: Option<Cookie>) -> Result<String, Response> {
    let user = if let Some(ref store) = store.0 {
        let redirect = || response::login_redirect(uri, false);
        let cookie = cookie.ok_or_else(redirect)?;
        let session_id = cookie.get("sid").ok_or_else(|| redirect())?;
        let session_id = hex::decode(session_id).map_err(|e| {
            error!("{}", e);
            redirect()
        })?;
        let (_, user) = store
            .lookup_session(&session_id)
            .map_err(|e| {
                error!("{}", e);
                response::internal_server_error()
            })?
            .ok_or_else(redirect)?;
        user
    } else {
        String::new()
    };
    Ok(user)
}

impl Authentication {
    pub fn extract(store: &DbStore, uri: &Uri, cookie: Option<Cookie>) -> Self {
        match check_session(&store, uri, cookie) {
            Ok(user) => Authentication::User(user),
            Err(response) => Authentication::Error(response),
        }
    }
}
