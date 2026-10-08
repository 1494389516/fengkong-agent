# Graph refresh reliability follow-up

PR #50 conservatively invalidated every device in a tenant/app for every observation.
With a fixed device-ID refresh order, continuous traffic could repeatedly refresh
the first 100 devices and starve the tail. This follow-up narrows invalidation and
makes refresh work fair and observable.

## Behavior

- For `community_v1` below row/node budgets, invalidate the entire connected
  component formed by the existing graph plus the incoming observation. Unrelated
  components remain available; a bridge invalidates both joined components.
- At row/node budgets, or with temporal/unknown primary or shadow algorithms,
  retain scope-wide invalidation. Snapshot eviction and clock-dependent weights
  can affect otherwise disconnected devices; partial graph output stays unavailable.
- Queue entries retain `dirty_since` and `scheduled_at` while already pending.
  Refresh selects by scheduled time and insertion order, not device name. A
  refreshed device invalidated again joins behind existing work. Failed refreshes
  move to the back without resetting their original waiting age.
- Existing four-column SQLite queues migrate additively. Legacy pending entries
  keep zero timestamps, take precedence, and conservatively show unknown/old age.
- Heartbeats include pending refresh count, oldest pending age, and availability
  of materialized primary feature rows. Pending/unavailable projections and worker
  failures mark health degraded even when the event bus is empty. Missing telemetry
  in a legacy heartbeat is explicitly degraded until the next heartbeat.

## Validation and remaining limits

Regression coverage includes 105 unrelated devices under repeated reporting,
105 connected devices with continuous invalidation and bounded refresh, indirect
neighbors (existing tests), queue migration, failed-refresh fairness, row/node
budget fallback, temporal fallback, and health visibility.

This does not guarantee every feature is continuously current under sustained
component changes. Changed components remain unavailable until refreshed. FIFO
progress requires a running worker with enough capacity; freshness still expires
after 300 seconds. Availability is measured over materialized feature rows, while
pending work separately accounts for outstanding projections. Truncated scopes
remain unavailable by design. No new enforcement policy is introduced for missing
graph features.
