# Graph time consistency follow-up

Baseline: main `5adb8bad253974f29ff112f8ca10ead1013271a4`.

## Reproduced defects

1. Health sampled wall time before reading the heartbeat. A valid atomic replacement
   during that read was reported as `heartbeat_future`; time spent blocked reading
   could also make an already stale heartbeat appear healthy.
2. Feature freshness only checked an upper age limit. A clock rollback or a stored
   infinite timestamp could leave future data readable and counted as available.
   Explicitly invalidated rows (`computed_at=0`) were also returned by callers that
   omitted TTL.

## Corrected behavior

- Health samples current time after reading and validating the heartbeat. An
  explicit `now` remains a caller-owned as-of time. Actual future timestamps are
  still rejected; no clock-skew tolerance is introduced.
- Feature writes require a positive finite numeric timestamp. Zero remains reserved
  for explicit invalidation; invalid writes cannot replace the previous value.
- Reads reject invalid, zero and future timestamps even with TTL disabled. Legacy
  invalid rows remain stored but unavailable. Availability counts use the same
  valid time window; the existing inclusive TTL boundary is preserved.
- Clock rollback can now cause temporary unavailability until time catches up or a
  valid projection replaces the row. This is preferable to presenting future data
  as fresh. No database migration, risk threshold or SDK changes are involved.

Seven deterministic regression tests use real files/SQLite plus controlled clocks
and I/O interleavings. These demonstrate adapter behavior, not observed production
incidents. The no-TTL invalidation case affects the generic store API; the graph
Decision lookup normally supplies a 300-second TTL.
