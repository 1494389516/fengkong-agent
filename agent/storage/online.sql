-- PostgreSQL schema v1; applied only by the migration command.
CREATE TABLE IF NOT EXISTS attestation_challenges (
          challenge_id TEXT PRIMARY KEY,tenant TEXT,app TEXT,principal TEXT,purpose TEXT,
          challenge BYTEA,expires_at DOUBLE PRECISION,consumed BIGINT DEFAULT 0);

CREATE TABLE IF NOT EXISTS attestation_counters (
          tenant TEXT, app TEXT, key_id TEXT, counter BIGINT,
          PRIMARY KEY(tenant,app,key_id));

CREATE TABLE IF NOT EXISTS decisions (
            tenant TEXT, app TEXT, event_id TEXT, fingerprint TEXT NOT NULL,
            decision_id TEXT UNIQUE NOT NULL, record TEXT NOT NULL,
            PRIMARY KEY(tenant, app, event_id));

CREATE TABLE IF NOT EXISTS enrolled_attestation_keys (
          tenant TEXT,app TEXT,key_id TEXT,principal TEXT,public_key BYTEA,app_id TEXT,
          PRIMARY KEY(tenant,app,key_id));

CREATE TABLE IF NOT EXISTS enrollment_evidence (
          tenant TEXT,app TEXT,key_id TEXT,attestation BYTEA,received_at DOUBLE PRECISION,
          PRIMARY KEY(tenant,app,key_id));

CREATE TABLE IF NOT EXISTS events (
            tenant TEXT, app TEXT, event_id TEXT, occurred_at DOUBLE PRECISION,
            recorded_at DOUBLE PRECISION, body TEXT NOT NULL,
            PRIMARY KEY(tenant, app, event_id));

CREATE TABLE IF NOT EXISTS evidence (
          evidence_id TEXT PRIMARY KEY, tenant TEXT, app TEXT, raw_envelope BYTEA,
          raw_payload BYTEA, raw_digest TEXT, received_at DOUBLE PRECISION, observation TEXT);

CREATE TABLE IF NOT EXISTS integration_events (
            event_id TEXT PRIMARY KEY,
            topic TEXT NOT NULL,
            event_key TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at DOUBLE PRECISION NOT NULL,
            published BIGINT NOT NULL DEFAULT 0,
            attempts BIGINT NOT NULL DEFAULT 0,
            lease_token TEXT,
            lease_until DOUBLE PRECISION,
            last_error TEXT
        );

CREATE TABLE IF NOT EXISTS integration_receipts(
          consumer_group TEXT,event_id TEXT,published BIGINT DEFAULT 0,
          attempts BIGINT DEFAULT 0,lease_token TEXT,lease_until DOUBLE PRECISION,last_error TEXT,
          PRIMARY KEY(consumer_group,event_id));

CREATE TABLE IF NOT EXISTS outbox (insertion_order BIGSERIAL UNIQUE, 
            decision_id TEXT PRIMARY KEY, body TEXT NOT NULL, exported BIGINT DEFAULT 0);

CREATE TABLE IF NOT EXISTS report_receipts (
          tenant TEXT, app TEXT, report_id TEXT, digest TEXT NOT NULL,
          evidence_id TEXT NOT NULL, nonce TEXT NOT NULL, principal TEXT NOT NULL,
          receipt TEXT NOT NULL, PRIMARY KEY(tenant,app,report_id),
          UNIQUE(tenant,app,principal,nonce));

CREATE INDEX IF NOT EXISTS events_account_order
          ON events(tenant, app, (body::jsonb ->> 'uid'), occurred_at, event_id);

CREATE INDEX IF NOT EXISTS events_scope_order ON events(tenant, app, occurred_at, event_id);

CREATE INDEX IF NOT EXISTS integration_events_claim
                      ON integration_events(topic,published,lease_until,created_at,event_id);

CREATE INDEX IF NOT EXISTS integration_events_pending
                      ON integration_events(published,created_at,event_id);
