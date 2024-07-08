-- Initialize the database.
-- Drop any existing data and create empty tables.

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS organisations;
DROP TABLE IF EXISTS records;

CREATE TABLE users (
  userId INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  firstName TEXT NOT NULL,
  lastName TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  phone TEXT
  );

CREATE TABLE organisations (
  orgId INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  name TEXT NOT NULL,
  description TEXT
);

CREATE TABLE records (
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  user_id integer NOT NULL REFERENCES users (userid),
  org_id integer NOT NULL REFERENCES organisations (orgid)
);
