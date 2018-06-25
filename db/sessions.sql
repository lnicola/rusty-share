create table sessions (
    id blob not null primary key,
    user_id integer not null references user(id),
    created datetime not null default current_timestamp,
    last_seen datetime not null default current_timestamp
) without rowid;
