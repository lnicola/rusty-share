use crate::db_store::DbStore;
use crate::response;
use crate::Response;
use futures::Async;
use headers::{Cookie, HeaderMapExt};
use log::error;
use tower_web::extract::ExtractFuture;
use tower_web::extract::{Context, Extract, Immediate};
use tower_web::util::BufStream;

pub enum Authentication {
    User(String),
    Error(Response),
}

fn check_session(store: &DbStore, context: &Context) -> Result<String, Response> {
    let user = if let Some(ref store) = store.0 {
        let redirect = || response::login_redirect(context.request().uri(), false);
        let cookie = context
            .request()
            .headers()
            .typed_get::<Cookie>()
            .ok_or_else(redirect)?;
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

fn get_store<B: BufStream>(context: &Context) -> Result<DbStore, tower_web::extract::Error> {
    let mut store = <DbStore as Extract<B>>::extract(context);
    match store.poll() {
        Ok(Async::Ready(_)) => Ok(store.extract()),
        Ok(Async::NotReady) => unreachable!(),
        Err(e) => Err(e),
    }
}

impl<B: BufStream> Extract<B> for Authentication {
    type Future = Immediate<Authentication>;

    fn extract(context: &Context) -> Self::Future {
        match get_store::<B>(context) {
            Ok(store) => {
                let r = match check_session(&store, &context) {
                    Ok(user) => Authentication::User(user),
                    Err(response) => Authentication::Error(response),
                };
                Immediate::ok(r)
            }
            Err(e) => Immediate::err(e),
        }
    }
}
