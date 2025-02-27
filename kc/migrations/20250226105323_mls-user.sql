-- Add migration script here
CREATE TABLE IF NOT EXISTS user (
    id integer primary key AUTOINCREMENT,
    user_id text,
    identity blob,
    group_list text,
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id)
);