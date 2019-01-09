use crate::db::{Conn, Store};
use crate::Config;
use log::error;
use tower_web::extract::{Context, Extract, Immediate};
use tower_web::util::BufStream;

pub struct DbStore(pub Option<Store>);

impl<B: BufStream> Extract<B> for DbStore {
    type Future = Immediate<DbStore>;

    fn extract(context: &Context) -> Self::Future {
        let config = context.config::<Config>().unwrap();
        let conn = match config.pool.as_ref().map(|pool| pool.get()) {
            None => Ok(None),
            Some(Ok(conn)) => Ok(Some(conn)),
            Some(Err(err)) => Err(err),
        };
        let store = match conn {
            Ok(Some(conn)) => Ok(DbStore(Some(Store::new(Conn::new(conn))))),
            Ok(None) => Ok(DbStore(None)),
            Err(err) => Err(err),
        };
        let store = store.map_err(|e| {
            error!("{}", e);
            // TODO
            tower_web::extract::Error::missing_argument()
        });
        Immediate::result(store)
    }
}
