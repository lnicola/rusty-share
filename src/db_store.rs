use crate::db::{Conn, Store};
use crate::Config;

pub struct DbStore(pub Option<Store>);

impl DbStore {
    pub fn extract(config: &Config) -> Result<Self, crate::Error> {
        let store = config
            .pool
            .as_ref()
            .map(|pool| pool.get())
            .transpose()?
            .map(Conn::new)
            .map(Store::new);
        Ok(DbStore(store))
    }
}
