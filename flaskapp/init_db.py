import os
import cs50
import psycopg2

db = cs50.SQL("postgresql://stage_2_user:stage_2_user@localhost:5432/stage_2")

# Execute a command: this creates a new table
db.execute('CREATE TABLE IF NOT EXISTS Users (userId TEXT PRIMARY KEY UNIQUE NOT NULL,'
                                 'firstName TEXT NOT NULL,'
                                 'lastName TEXT NOT NULL,'
                                 'email TEXT UNIQUE NOT NULL,'
                                 'password TEXT NOT NULL,'
                                 'phone TEXT);'
                                 )

db.execute('CREATE TABLE IF NOT EXISTS organisations (orgId TEXT PRIMARY KEY UNIQUE NOT NULL,'
                                 'name TEXT NOT NULL,'
                                 'description TEXT);'
                                 )

db.execute('CREATE TABLE IF NOT EXISTS records (id serial PRIMARY KEY UNIQUE NOT NULL,'
                                 'user_id TEXT NOT NULL REFERENCES users (userid),'
                                 'org_id TEXT NOT NULL REFERENCES organisations (orgid));'
                                 )