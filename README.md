# Hosted replay containment harness

This repository contains a bounded, secret-free GitHub-hosted containment harness. The current branch diagnostic answers one narrower question: can Docker directly create and run the pinned PG17 image on the packet's internal isolated network while publishing `5432` only as `127.0.0.1:56422`, without involving the Supabase CLI?

The smoke does not log in to Supabase, contact a Supabase project, use application migrations, inspect Auth rows, or replay application/provider/user data.

## Source contract

The pinned CLI source at commit `6d4c19870ed213ba7f682f117d0345c8a40bfa94` establishes the path used here:

- `supabase db start` starts only the local database lifecycle.
- For PG17, enabled Auth contributes a short-lived job whose exact command is `gotrue migrate`.
- Realtime, Storage, API, Studio, local SMTP, Edge Runtime, Analytics, pooling, application migrations, and seed loading are disabled in the committed profile.
- The required image defaults in that source are Postgres `17.6.1.143` and GoTrue `v2.192.0`.

Exact external pins and digests are recorded in [`pins.json`](pins.json).

## Run

Dispatch **Hosted replay direct Docker port diagnostic** manually in GitHub Actions. There are no push, pull-request, schedule, or reusable-workflow triggers. The workflow selects `direct-port`; the original CLI containment path remains available in the script as `run` but is not invoked by this diagnostic.

The diagnostic job ends in one of two states:

- `DIRECT_DOCKER_PORT_PATH_PASS` only when every runner, pinned-image, isolated-network, direct-container, loopback-binding, stable-health, and cleanup gate passes. This is not an application-replay admission.
- `BLOCKED: <SANITIZED_CODE>` when any contract fails. The harness does not weaken isolation or retry with broader settings.

The GitHub **Set up job** log is the authoritative exact hosted-runner image capture. The direct receipt intentionally excludes raw runner identity fields; the runner gates still require Ubuntu 24.04, x86_64, and Docker client/server `>=28` before Docker resources are created.

## Public evidence

Only `artifacts/containment-smoke.json` is uploaded. In direct mode it is a strict allowlist containing status, stable failure codes, hashed image/network/container identities, binding class/counts, health/restart/OOM state, timings, and cleanup counts. Raw CLI, Docker, health, credential, environment, SQL, and connection output is excluded; packet scratch is removed by exact shell cleanup before the job exits.

Repository-level Actions artifact and log retention must remain set to 7 days. The workflow independently pins the uploaded artifact to 7 days.

## Local verification

The static contract suite uses only Python's standard library:

```sh
python3 -m unittest discover -s tests -v
```

The stateful smoke is intentionally runner-only. Local verification does not pull images or create Docker resources.
