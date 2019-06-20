create table user_shares (
    user_id integer not null references users(id),
    share_id integer not null references shares(id),
    primary key (user_id, share_id) on conflict ignore
) without rowid;
