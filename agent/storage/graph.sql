-- PostgreSQL schema v1; applied only by the migration command.
CREATE TABLE IF NOT EXISTS projection_epoch(singleton BIGINT PRIMARY KEY CHECK(singleton=1), epoch BIGINT NOT NULL);
INSERT INTO projection_epoch VALUES(1,0) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS dirty_devices (insertion_order BIGSERIAL UNIQUE, 
          tenant TEXT NOT NULL, app TEXT NOT NULL, device_id TEXT NOT NULL,
          entity_generation TEXT NOT NULL, dirty_since DOUBLE PRECISION NOT NULL DEFAULT 0, scheduled_at DOUBLE PRECISION NOT NULL DEFAULT 0,
          PRIMARY KEY(tenant,app,device_id,entity_generation));

CREATE TABLE IF NOT EXISTS observations (
          evidence_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, app TEXT NOT NULL,
          uid TEXT, device_id TEXT NOT NULL, entity_generation TEXT NOT NULL,
          ip TEXT, observed_at DOUBLE PRECISION NOT NULL, recorded_at DOUBLE PRECISION NOT NULL);

CREATE INDEX IF NOT EXISTS dirty_queue ON dirty_devices(scheduled_at);

CREATE INDEX IF NOT EXISTS graph_device_time
          ON observations(tenant,app,device_id,entity_generation,observed_at);

CREATE INDEX IF NOT EXISTS graph_scope_recorded
          ON observations(tenant,app,recorded_at DESC,evidence_id DESC);

CREATE INDEX IF NOT EXISTS graph_uid_time
          ON observations(tenant,app,uid,observed_at);
