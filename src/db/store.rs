use super::models::User;
use super::schema::{sessions, users};
use diesel::result::Error;
use diesel::{
    self, Connection, ExpressionMethods, OptionalExtension, QueryDsl, QueryResult, RunQueryDsl,
    SqliteConnection,
};
use log::{error, log};

pub struct Store(SqliteConnection);

impl Store {
    pub fn new(connection: SqliteConnection) -> Self {
        Store(connection)
    }

    pub fn initialize_database(&self) -> QueryResult<()> {
        diesel::sql_query(include_str!("../../db/users.sql")).execute(self.connection())?;
        diesel::sql_query(include_str!("../../db/sessions.sql")).execute(self.connection())?;
        Ok(())
    }

    pub fn insert_user(&self, name: &str, password: &str) -> QueryResult<i32> {
        diesel::insert_into(users::table)
            .values((users::name.eq(name), users::password.eq(password)))
            .execute(self.connection())?;
        super::last_inserted_row_id(self.connection())
    }

    pub fn update_password(&self, user_id: i32, password: &str) -> QueryResult<usize> {
        diesel::update(users::table.find(user_id))
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
            if let Err(e) = diesel::update(sessions::table.find(id))
                .set(sessions::last_seen.eq(diesel::dsl::now))
                .execute(self.connection())
            {
                error!("Unable to update session time for user {}: {}", user_id, e);
            }

            let user_name = users::table
                .find(user_id)
                .select(users::name)
                .first::<String>(self.connection())?;

            Ok(Some((user_id, user_name)))
        } else {
            Ok(None)
        }
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
