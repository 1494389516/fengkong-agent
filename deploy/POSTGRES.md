# PostgreSQL deployment and offline migration

Production Compose uses PostgreSQL 16. Local examples retain SQLite unless
`FK_STORAGE_BACKEND=postgres` is explicit. There is no fallback from an unavailable
PostgreSQL server to an empty local database. `cloudphone-risk-detector` upload
contracts do not change.

## Provision before starting application services

1. Keep the authentication, signing and mounted-file setup from `README.md`.
   Every registered tenant/app gets five schemas. Their names derive from the
   tenant/app, not a container path. A graph worker without request context must
   have exactly one registered domain matching `FK_DATA_DIR`. Use one graph
   worker deployment per domain. All stores must use the same PostgreSQL database.
2. Create `secrets/postgres-admin-password` and an `admin-database-url` readable by
   the maintenance container UID. Restrict secret files to their service account.
   The admin URL targets `postgres:5432/fengkong` inside Compose. Start only the
   database: `docker compose up -d postgres`.
3. Run `postgres_roles.sql` through an administrator psql session. Set separate
   strong passwords with `\password fk_collector`, etc. Create one URL file per
   service: `collector-database-url`, `runtime-database-url`,
   `projector-database-url`, `agent-database-url`, `reviewer-database-url`, and
   `graph-database-url`. For example, the runtime file contains
   `postgresql://fk_runtime:<URL-encoded-password>@postgres:5432/fengkong`.
   URL files accept either a PostgreSQL URI or a libpq keyword connection string.
   Do not use the admin URL in application containers.
4. Run `docker compose --profile maintenance run --rm storage-migrate`.
   This creates schemas and grants the dedicated service roles. Runtime code
   requires the expected schema version and does not execute DDL. Repeat this
   step for every tenant/app namespace using the corresponding registry/dataset.
5. For a fresh installation, start the application services. For an existing
   installation, first complete the import below.

Use TLS with certificate verification when the database is outside the local
Compose network. Production backup, replication and capacity sizing belong to
the operator's PostgreSQL deployment; the bundled container is a single node.

## Import existing SQLite state

Stop **all** Collector, Decision, graph, projector, Agent, review and knowledge
writers. Wait for live leases to expire and retain filesystem/database backups.
An unfinished external call remains ambiguous after migration; no replay erases
its budget receipt or automatically assumes the provider did nothing.

Run the maintenance container with this command override:

```sh
docker compose --profile maintenance run --rm storage-migrate \
  python -m agent.storage.migrate --import-sqlite --writers-stopped
```

The source roots must match the mounted `/tenant` and `/agent-state` layout.
If a pre-separation `online.sqlite3` still contains legacy investigation tables,
run the existing `agent.migrate_investigations` SQLite migration first.

Import uses read-only SQLite snapshots and one PostgreSQL transaction for all
five stores. It verifies source integrity, records per-table counts and content
digests, preserves BLOB bytes and historical ordering, and rejects live leases,
unsupported tables or a populated target. Repeating the identical import is a
no-op; importing a different source into that namespace is rejected. Source
databases are not modified. `--writers-stopped` is an operator assertion, not a
distributed stop command: never run it against active writers.

The projector uses durable per-decision receipts, not imported SQLite rowid or a
PostgreSQL sequence watermark. Receipt, case revision and investigation task
commit atomically. Rollback before PostgreSQL activation can restore the original
deployment from its backup. After new PostgreSQL writes, reverting requires a
deliberate reverse migration; pointing back at stale SQLite files loses new work.

## Runtime guarantees and remaining boundaries

- Evidence + accepted event, and decision + business event + outbox, share their
  original transactions. Read/check/write transactions retain a per-namespace,
  per-store advisory lock; this first backend does not promise unlimited write
  scaling. LLM calls run outside these database transactions.
- Queue claims use row locks with `SKIP LOCKED`; lease tokens fence completion.
  Independent consumer groups retain their own receipts. External side effects
  still need their own idempotency or ambiguous-call handling.
- Graph projection uses a database session lock and a monotonically increasing
  fencing epoch. Replacement workers fence publication and dirty-queue deletion
  by the old worker, including after its lock connection fails.
- Completed primary/shadow features publish in one transaction with a persisted
  revision. `FK_GRAPH_REFRESH_POLICY=strict` remains the default.
  `bounded_previous` explicitly permits the previous complete version while
  refreshing, within the existing 300-second TTL. It exposes `refreshing`, the
  original computation time and feature revision in the decision evidence.
  Future timestamps, expired values, truncated graphs and changed algorithms
  remain unavailable. Refresh failure never extends the old version's TTL.
- Historical feature versions need a retention policy aligned with decision
  evidence retention; this release does not silently delete them.
- Role grants are additive and require dedicated roles without previous grants
  or powerful memberships. Agent credentials can read evidence, but cannot write
  evidence, decisions or release bundles. PostgreSQL enforces immutable revision
  and review history in addition to API authorization.
- Tenant auxiliary JSON data, pinned knowledge archives, release bundles and
  audit files remain explicitly mounted artifacts. PostgreSQL does not make
  those artifacts magically shared across hosts. Deploy immutable shared copies
  and an appropriate audit sink before distributing those services.
- PostgreSQL history queries use statement deadlines and row/byte limits;
  SQLite's VM-instruction limit has no portable PostgreSQL equivalent.

For an offline knowledge publisher, additionally grant
`--grant knowledge=fk_knowledge` and use that credential only for index ingestion.
DBOS is evaluated separately under `experiments/dbos`; it is not a runtime
dependency or a replacement for business budgets, evidence or approval policy.
