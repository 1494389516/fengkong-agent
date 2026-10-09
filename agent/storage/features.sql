-- PostgreSQL schema v1; applied only by the migration command.
CREATE TABLE IF NOT EXISTS entity_features (
          tenant TEXT NOT NULL, app TEXT NOT NULL, entity_type TEXT NOT NULL,
          entity_id TEXT NOT NULL, generation TEXT NOT NULL, feature_set TEXT NOT NULL,
          body TEXT NOT NULL, computed_at DOUBLE PRECISION NOT NULL, refresh_pending BIGINT NOT NULL DEFAULT 0,
          PRIMARY KEY(tenant,app,entity_type,entity_id,generation,feature_set));

CREATE TABLE IF NOT EXISTS feature_versions(
  revision TEXT PRIMARY KEY,tenant TEXT,app TEXT,entity_type TEXT,entity_id TEXT,
  generation TEXT,feature_set TEXT,body TEXT,computed_at DOUBLE PRECISION);
