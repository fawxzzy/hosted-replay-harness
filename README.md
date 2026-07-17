# Hosted replay containment harness

This repository contains one bounded, secret-free GitHub-hosted containment smoke. It answers one question: can Supabase CLI `v2.109.1` complete its PG17 database-only initialization on an Ubuntu 24.04 standard runner while its Postgres and one-shot GoTrue migration containers have no external egress, attach only to one packet-owned Docker network, and publish Postgres only on `127.0.0.1:56422`?

The smoke does not log in to Supabase, contact a Supabase project, use application migrations, inspect Auth rows, or replay application/provider/user data.

## Source contract

The pinned CLI source at commit `6d4c19870ed213ba7f682f117d0345c8a40bfa94` establishes the path used here:

- `supabase db start` starts only the local database lifecycle.
- For PG17, enabled Auth contributes a short-lived job whose exact command is `gotrue migrate`.
- Realtime, Storage, API, Studio, local SMTP, Edge Runtime, Analytics, pooling, application migrations, and seed loading are disabled in the committed profile.
- The required image defaults in that source are Postgres `17.6.1.143` and GoTrue `v2.192.0`.

Exact external pins and digests are recorded in [`pins.json`](pins.json).

## Run

Dispatch **Hosted replay containment smoke** manually in GitHub Actions. There are no push, pull-request, schedule, or reusable-workflow triggers.

The job ends in one of two states:

- `CONTAINMENT_SMOKE_PASS` only when every runner, image, network, container, port, database canary, and cleanup gate passes.
- `BLOCKED: <SANITIZED_CODE>` when any contract fails. The harness does not weaken isolation or retry with broader settings.

The GitHub **Set up job** log is the authoritative exact hosted-runner image capture. The sanitized receipt also records Ubuntu release identity, kernel, architecture, and an `/etc/os-release` digest.

## Public evidence

Only `artifacts/containment-smoke.json` is uploaded. It contains status, stable failure codes, versions, digests, image IDs, network identity, boolean gates, bounded counts, and cleanup counts. Raw CLI, Docker, and SQL output stays in packet scratch and is removed by `if: always`-equivalent shell cleanup before the job exits.

Repository-level Actions artifact and log retention must remain set to 7 days. The workflow independently pins the uploaded artifact to 7 days.

## Local verification

The static contract suite uses only Python's standard library:

```sh
python3 -m unittest discover -s tests -v
```

The stateful smoke is intentionally runner-only. Local verification does not pull images or create Docker resources.
