create table users (
    id integer not null primary key,
    name text not null unique,
    password text not null
);
