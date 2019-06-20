use crate::db::{Conn, Store};
use crate::Pool;

pub struct DbStore(pub Option<Store>);

impl DbStore {
    pub fn extract(pool: &Option<Pool>) -> Result<Self, crate::Error> {
        let store = pool
            .as_ref()
            .map(|pool| pool.get())
            .transpose()?
            .map(Conn::new)
            .map(Store::new);
        Ok(DbStore(store))
    }
}
