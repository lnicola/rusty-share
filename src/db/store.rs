use super::models::{AccessLevel, User};
use super::schema::{sessions, shares, user_shares, users};
use diesel::r2d2::{ConnectionManager, PooledConnection};
use diesel::result::Error;
use diesel::sql_types::{Integer, Nullable};
use diesel::{
    self, dsl, BoolExpressionMethods, Connection, ExpressionMethods, IntoSql,
    NullableExpressionMethods, OptionalExtension, QueryDsl, QueryResult, RunQueryDsl,
    SqliteConnection,
};
use std::path::PathBuf;

type Conn = PooledConnection<ConnectionManager<SqliteConnection>>;

pub struct SqliteStore(Conn);

no_arg_sql_function!(last_insert_rowid, Integer);

pub fn last_inserted_row_id(connection: &SqliteConnection) -> QueryResult<i32> {
    diesel::select(last_insert_rowid).get_result(connection)
}

impl SqliteStore {
    pub fn new(connection: Conn) -> Self {
        Self(connection)
    }

    pub fn initialize_database(&self) -> QueryResult<()> {
        diesel::sql_query(include_str!("../../db/users.sql")).execute(self.connection())?;
        diesel::sql_query(include_str!("../../db/sessions.sql")).execute(self.connection())?;
        diesel::sql_query(include_str!("../../db/shares.sql")).execute(self.connection())?;
        diesel::sql_query(include_str!("../../db/user_shares.sql")).execute(self.connection())?;
        Ok(())
    }

    pub fn insert_user(&self, name: &str, password: &str) -> QueryResult<i32> {
        diesel::insert_into(users::table)
            .values((users::name.eq(name), users::password.eq(password)))
            .execute(self.connection())?;
        self::last_inserted_row_id(self.connection())
    }

    pub fn update_password_by_id(&self, user_id: i32, password: &str) -> QueryResult<usize> {
        diesel::update(users::table.find(user_id))
            .set(users::password.eq(password))
            .execute(self.connection())
    }

    pub fn update_password_by_name(&self, name: &str, password: &str) -> QueryResult<usize> {
        diesel::update(users::table.filter(users::name.eq(name)))
            .set(users::password.eq(password))
            .execute(self.connection())
    }

    pub fn find_user(&self, name: &str) -> QueryResult<Option<User>> {
        users::table
            .filter(users::name.eq(name))
            .first::<User>(self.connection())
            .optional()
    }

    pub fn create_session(&self, id: &[u8], user_id: i32) -> QueryResult<()> {
        diesel::insert_into(sessions::table)
            .values((sessions::id.eq(id), sessions::user_id.eq(user_id)))
            .execute(self.connection())?;
        Ok(())
    }

    pub fn lookup_session(&self, id: &[u8]) -> QueryResult<Option<(i32, String)>> {
        let user_id = sessions::table
            .find(id)
            .select(sessions::user_id)
            .first::<i32>(self.connection())
            .optional()?;

        if let Some(user_id) = user_id {
            let user_name = users::table
                .find(user_id)
                .select(users::name)
                .first::<String>(self.connection())?;

            Ok(Some((user_id, user_name)))
        } else {
            Ok(None)
        }
    }

    pub fn lookup_share(&self, name: &str, user_id: Option<i32>) -> QueryResult<Option<PathBuf>> {
        shares::table
            .filter(shares::name.eq(name))
            .filter(
                shares::access_level
                    .eq(AccessLevel::Public as i32)
                    .or(shares::access_level
                        .eq(AccessLevel::Authenticated as i32)
                        .and(user_id.into_sql::<Nullable<Integer>>().is_not_null()))
                    .or(shares::access_level
                        .eq(AccessLevel::Restricted as i32)
                        .and(dsl::exists(
                            user_shares::table.filter(
                                user_shares::user_id
                                    .nullable()
                                    .eq(user_id)
                                    .and(user_shares::share_id.eq(shares::id)),
                            ),
                        ))),
            )
            .select(shares::path)
            .first::<String>(self.connection())
            .map(PathBuf::from)
            .optional()
    }

    pub fn get_share_names(&self, user_id: Option<i32>) -> QueryResult<Vec<String>> {
        shares::table
            .select(shares::name)
            .filter(
                shares::access_level
                    .eq(AccessLevel::Public as i32)
                    .or(shares::access_level
                        .eq(AccessLevel::Authenticated as i32)
                        .and(user_id.into_sql::<Nullable<Integer>>().is_not_null()))
                    .or(shares::access_level
                        .eq(AccessLevel::Restricted as i32)
                        .and(dsl::exists(
                            user_shares::table.filter(
                                user_shares::user_id
                                    .nullable()
                                    .eq(user_id)
                                    .and(user_shares::share_id.eq(shares::id)),
                            ),
                        ))),
            )
            .load::<String>(self.connection())
    }

    pub fn create_share(&self, name: &str, path: &str) -> QueryResult<i32> {
        diesel::insert_into(shares::table)
            .values((
                shares::name.eq(name),
                shares::path.eq(path),
                shares::access_level.eq(AccessLevel::Authenticated as i32),
            ))
            .execute(self.connection())?;
        self::last_inserted_row_id(self.connection())
    }

    pub fn transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
        E: From<Error>,
    {
        self.connection().transaction(f)
    }

    #[inline]
    fn connection(&self) -> &SqliteConnection {
        &self.0
    }
}
