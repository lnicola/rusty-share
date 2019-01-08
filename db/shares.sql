create table shares (
    id integer not null primary key,
    name text not null unique,
    path text not null
);
