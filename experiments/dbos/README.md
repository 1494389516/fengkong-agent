# DBOS investigation recovery experiment

Install the pinned experimental requirements in a separate environment. Set
`FK_DBOS_DATABASE_URL` to a disposable PostgreSQL database with schema creation
permission, then run:

```sh
python -m experiments.dbos.recovery_probe
```

The probe checkpoints synthetic evidence and a plan produced/validated by the
actual Agent plan module. It kills the worker after the report step starts, then
starts a new process against the same checkpoints. Success requires one evidence
execution, one plan execution and two report attempts. No LLM is called, no real
case is persisted, and no candidate policy can be published. Each probe creates
an isolated `dbos_probe_*` schema; remove the disposable database after inspecting
its results.

Adoption decision: keep DBOS experimental. The recovery probe verifies completed
step replay across a process crash, not multi-host failover, application upgrades,
provider exactly-once execution or throughput. Production adoption additionally
requires integrating authenticated worker admission, the existing budget/run
ledger, ambiguous-call interruption, version-compatible recovery and the chosen
multi-worker recovery coordinator. Installing DBOS alone does not replace those
contracts.
