-- PostgreSQL schema v1; applied only by the migration command.
CREATE TABLE IF NOT EXISTS chunks(chunk_id TEXT PRIMARY KEY,body TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
