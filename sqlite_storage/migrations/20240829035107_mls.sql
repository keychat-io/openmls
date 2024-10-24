-- Add migration script here
-- create table if not exists identity (
--     id integer primary key AUTOINCREMENT,
--     iden_key blob UNIQUE,
--     iden_value blob,
--     createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
-- );

create table if not exists identity (
    id integer primary key AUTOINCREMENT,
    user text,
    iden_key blob,
    iden_value blob,
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user, iden_key)
);

create table if not exists user (
    id integer primary key AUTOINCREMENT,
    user_id text,
    identity blob,
    group_list text,
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id)
);