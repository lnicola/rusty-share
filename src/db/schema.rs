table! {
    sessions (id) {
        id -> Binary,
        user_id -> Integer,
        created -> Timestamp,
        last_seen -> Timestamp,
    }
}

table! {
    users (id) {
        id -> Integer,
        name -> Text,
        password -> Text,
    }
}

table! {
    shares (id) {
        id -> Integer,
        name -> Text,
        path -> Text,
    }
}

allow_tables_to_appear_in_same_query!(sessions, users,);
