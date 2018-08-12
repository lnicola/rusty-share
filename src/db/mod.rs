pub use self::store::Store;
use diesel::r2d2::{ConnectionManager, PooledConnection};
use diesel::sql_types::Integer;
use diesel::{self, QueryResult, RunQueryDsl, SqliteConnection};
use std::ops::Deref;

mod models;
mod schema;
mod store;

pub struct Conn(PooledConnection<ConnectionManager<SqliteConnection>>);

impl Conn {
    pub fn new(conn: PooledConnection<ConnectionManager<SqliteConnection>>) -> Self {
        Conn(conn)
    }
}

impl Deref for Conn {
    type Target = SqliteConnection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

no_arg_sql_function!(last_insert_rowid, Integer);

pub fn last_inserted_row_id(connection: &SqliteConnection) -> QueryResult<i32> {
    diesel::select(last_insert_rowid).get_result(connection)
}
