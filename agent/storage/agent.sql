-- PostgreSQL schema v1; applied only by the migration command.
CREATE TABLE IF NOT EXISTS agent_store_meta(key TEXT PRIMARY KEY,value TEXT);

CREATE TABLE IF NOT EXISTS budget_contracts(task_id TEXT PRIMARY KEY, body TEXT);

CREATE TABLE IF NOT EXISTS budget_receipts(
            task_id TEXT, receipt_id TEXT, component TEXT, reserved BIGINT,
            actual_used BIGINT DEFAULT 0, estimated_used BIGINT DEFAULT 0,
            status TEXT, worker_token TEXT, PRIMARY KEY(task_id,receipt_id));

CREATE TABLE IF NOT EXISTS case_arbitrations(
        arbitration_id TEXT PRIMARY KEY, case_id TEXT, revision BIGINT,
        principal TEXT, request_id TEXT, request_digest TEXT, body TEXT,
        UNIQUE(principal,request_id));

CREATE TABLE IF NOT EXISTS case_reviews(
        review_id TEXT PRIMARY KEY, task_id TEXT, principal TEXT, request_id TEXT,
        request_digest TEXT, body TEXT, UNIQUE(principal,request_id));

CREATE TABLE IF NOT EXISTS case_revisions(
      case_id TEXT, revision BIGINT, snapshot_id TEXT UNIQUE, body TEXT NOT NULL,
      PRIMARY KEY(case_id,revision));

CREATE TABLE IF NOT EXISTS cases(insertion_order BIGSERIAL UNIQUE, case_id TEXT PRIMARY KEY, tenant TEXT, app TEXT,
          entity TEXT, bucket BIGINT, body TEXT, UNIQUE(tenant,app,entity,bucket));

CREATE TABLE IF NOT EXISTS investigation_runs(
        run_id TEXT PRIMARY KEY,task_id TEXT,attempt BIGINT,fencing_epoch BIGINT,
        worker_token TEXT,started_at DOUBLE PRECISION,deadline DOUBLE PRECISION,status TEXT,
        UNIQUE(task_id,attempt));

CREATE TABLE IF NOT EXISTS investigation_seen(decision_id TEXT PRIMARY KEY);

CREATE TABLE IF NOT EXISTS investigation_tasks(insertion_order BIGSERIAL UNIQUE, task_id TEXT PRIMARY KEY,case_id TEXT,
          snapshot TEXT, status TEXT, result TEXT, lease_until DOUBLE PRECISION DEFAULT 0, lease_token TEXT);

CREATE TABLE IF NOT EXISTS projection_cursor(id BIGINT PRIMARY KEY CHECK(id=1), position BIGINT NOT NULL);

CREATE TABLE IF NOT EXISTS reservation_contracts(
            task_id TEXT, receipt_id TEXT, component TEXT, maximum BIGINT, ceiling BIGINT,
            PRIMARY KEY(task_id,receipt_id));

CREATE TABLE IF NOT EXISTS resource_receipts(
            task_id TEXT, receipt_id TEXT, resource TEXT, amount BIGINT, worker_token TEXT,
            PRIMARY KEY(task_id,receipt_id,resource));

CREATE TABLE IF NOT EXISTS run_contracts(
            task_id TEXT PRIMARY KEY, privacy_salt TEXT NOT NULL, created_at DOUBLE PRECISION);

CREATE TABLE IF NOT EXISTS run_steps(
            task_id TEXT, node_id TEXT, kind TEXT, input_digest TEXT,
            status TEXT, output TEXT, worker_token TEXT,
            PRIMARY KEY(task_id,node_id));

INSERT INTO projection_cursor VALUES(1,0) ON CONFLICT DO NOTHING;
