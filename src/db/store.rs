use super::models::{AccessLevel, User};
use super::schema::{sessions, shares, user_shares, users};
use crate::Error;
use diesel::query_builder::AsQuery;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sql_types::{Integer, Nullable};
use diesel::{
    self, dsl, BoolExpressionMethods, ExpressionMethods, IntoSql, NullableExpressionMethods,
    OptionalExtension, QueryDsl, RunQueryDsl, SqliteConnection,
};
use std::path::PathBuf;

type Pool = r2d2::Pool<ConnectionManager<SqliteConnection>>;
type DbResult<T> = Result<T, Error>;

#[derive(Clone)]
pub struct SqliteStore(Pool);

no_arg_sql_function!(last_insert_rowid, Integer);

pub fn last_inserted_row_id(connection: &SqliteConnection) -> DbResult<i32> {
    let row_id = diesel::select(last_insert_rowid).get_result(connection)?;
    Ok(row_id)
}

impl SqliteStore {
    pub fn new(url: &str) -> Self {
        Self(Pool::new(ConnectionManager::new(url.clone())).unwrap())
    }

    pub fn initialize_database(&self) -> DbResult<()> {
        let conn = self.0.get()?;
        diesel::sql_query(include_str!("../../db/users.sql")).execute(&conn)?;
        diesel::sql_query(include_str!("../../db/sessions.sql")).execute(&conn)?;
        diesel::sql_query(include_str!("../../db/shares.sql")).execute(&conn)?;
        diesel::sql_query(include_str!("../../db/user_shares.sql")).execute(&conn)?;
        Ok(())
    }

    pub fn insert_user(&self, name: &str, password: &str) -> DbResult<i32> {
        let conn = self.0.get()?;
        diesel::insert_into(users::table)
            .values((users::name.eq(name), users::password.eq(password)))
            .execute(&conn)?;
        self::last_inserted_row_id(&conn)
    }

    pub fn users_exist(&self) -> DbResult<bool> {
        let conn = self.0.get()?;
        let r = diesel::select(diesel::dsl::exists(users::table.as_query())).get_result(&conn)?;
        Ok(r)
    }

    pub fn update_password_by_id(&self, user_id: i32, password: &str) -> DbResult<usize> {
        let conn = self.0.get()?;
        let count = diesel::update(users::table.find(user_id))
            .set(users::password.eq(password))
            .execute(&conn)?;
        Ok(count)
    }

    pub fn update_password_by_name(&self, name: &str, password: &str) -> DbResult<usize> {
        let conn = self.0.get()?;
        let count = diesel::update(users::table.filter(users::name.eq(name)))
            .set(users::password.eq(password))
            .execute(&conn)?;
        Ok(count)
    }

    pub fn find_user(&self, name: &str) -> DbResult<Option<User>> {
        let conn = self.0.get()?;
        let user = users::table
            .filter(users::name.eq(name))
            .first::<User>(&conn)
            .optional()?;
        Ok(user)
    }

    pub fn create_session(&self, id: &[u8], user_id: i32) -> DbResult<()> {
        let conn = self.0.get()?;
        diesel::insert_into(sessions::table)
            .values((sessions::id.eq(id), sessions::user_id.eq(user_id)))
            .execute(&conn)?;
        Ok(())
    }

    pub fn lookup_session(&self, id: &[u8]) -> DbResult<Option<(i32, String)>> {
        let conn = self.0.get()?;
        let user_id = sessions::table
            .find(id)
            .select(sessions::user_id)
            .first::<i32>(&conn)
            .optional()?;

        if let Some(user_id) = user_id {
            let user_name = users::table
                .find(user_id)
                .select(users::name)
                .first::<String>(&conn)?;

            Ok(Some((user_id, user_name)))
        } else {
            Ok(None)
        }
    }

    pub fn lookup_share(&self, name: &str, user_id: Option<i32>) -> DbResult<Option<PathBuf>> {
        let conn = self.0.get()?;
        let share = shares::table
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
            .first::<String>(&conn)
            .map(PathBuf::from)
            .optional()?;
        Ok(share)
    }

    pub fn get_share_names(&self, user_id: Option<i32>) -> DbResult<Vec<String>> {
        let conn = self.0.get()?;
        let shares = shares::table
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
            .load::<String>(&conn)?;
        Ok(shares)
    }

    pub fn create_share(&self, name: &str, path: &str) -> DbResult<i32> {
        let conn = self.0.get()?;
        diesel::insert_into(shares::table)
            .values((
                shares::name.eq(name),
                shares::path.eq(path),
                shares::access_level.eq(AccessLevel::Authenticated as i32),
            ))
            .execute(&conn)?;
        self::last_inserted_row_id(&conn)
    }
}
