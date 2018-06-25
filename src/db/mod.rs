pub use self::store::Store;
use diesel::sql_types::Integer;
use diesel::{self, Connection, ConnectionResult, QueryResult, RunQueryDsl, SqliteConnection};

mod models;
mod schema;
mod store;

no_arg_sql_function!(last_insert_rowid, Integer);

pub fn last_inserted_row_id(connection: &SqliteConnection) -> QueryResult<i32> {
    diesel::select(last_insert_rowid).get_result(connection)
}

pub fn establish_connection() -> ConnectionResult<SqliteConnection> {
    // let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let database_url = "rusty-share.db";
    SqliteConnection::establish(&database_url)
}
