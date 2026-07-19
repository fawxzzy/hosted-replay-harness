# Hosted replay containment harness

This repository contains one bounded, secret-free GitHub-hosted containment smoke. It answers one question: can Supabase CLI `v2.109.1` complete its PG17 database-only initialization on an Ubuntu 24.04 standard runner while its Postgres and one-shot GoTrue migration containers have no external egress, attach only to one packet-owned Docker network, and publish Postgres only on `127.0.0.1:56422`?

The smoke does not log in to Supabase, contact a Supabase project, use application migrations, inspect Auth rows, or replay application/provider/user data.

## Fitness source adapter

The stacked Fitness adapter freezes the exact public 101-migration base plus
the single PR #108 migration as a 102-object manifest and defines a
synthetic-only, full-chain replay. Its manual workflow targets only the
repository-scoped `fp-hosted-replay-jit-v1` ephemeral runner label. It cannot
run on the standard hosted workflow and has no host-Docker fallback.

This repository change is source-only. The JIT runtime, any chargeable
infrastructure, exact-head review, and a single workflow dispatch remain held
under separate authority. See
[`docs/FITNESS_FULL_CHAIN_REPLAY_CONTRACT.md`](docs/FITNESS_FULL_CHAIN_REPLAY_CONTRACT.md).

## Source contract

The pinned CLI source at commit `6d4c19870ed213ba7f682f117d0345c8a40bfa94` establishes the path used here:

- `supabase db start` starts only the local database lifecycle.
- The immutable Linux asset is a two-member executable closure: the Bun entrypoint `supabase` and its adjacent Go sidecar `supabase-go`. The loader validates the complete tar header denominator, exact sizes, hashes, ELF identities, and adjacency before Docker access; no `SUPABASE_GO_BINARY` override is used.
- For PG17, enabled Auth contributes a short-lived job whose exact command is `gotrue migrate`.
- Realtime, Storage, API, Studio, local SMTP, Edge Runtime, Analytics, pooling, application migrations, and seed loading are disabled in the committed profile.
- The required image defaults in that source are Postgres `17.6.1.143` and GoTrue `v2.192.0`.

Exact external pins and digests are recorded in [`pins.json`](pins.json).

## Run

Dispatch **Hosted replay containment smoke** manually in GitHub Actions. There are no push, pull-request, schedule, reusable-workflow, or mode-selection triggers. The workflow invokes the CLI containment path exactly once.

The job ends in one of two states:

- `CONTAINMENT_SMOKE_PASS` only when every runner, image, network, lifecycle, port, database canary, and cleanup gate passes. This proves containment only; it is not an application-replay admission.
- `BLOCKED: <SANITIZED_CODE>` when any contract fails. The harness does not weaken isolation or retry with broader settings.

The GitHub **Set up job** log is the authoritative exact hosted-runner image capture. The sanitized receipt records Ubuntu release identity, kernel, architecture, and an `/etc/os-release` digest. Runner gates require Ubuntu 24.04, x86_64, and Docker client/server `>=28` before Docker resources are created.

## Public evidence

Only `artifacts/containment-smoke.json` is uploaded. It contains status, stable failure codes, versions, pinned digests, hashed container/network identities, lifecycle counts, exact-network correlation booleans, bounded database canary counts, and cleanup counts. Raw CLI, Docker, health, credential, environment, SQL, and connection output is excluded; packet scratch is removed by exact shell cleanup before the job exits.

Repository-level Actions artifact and log retention must remain set to 7 days. The workflow independently pins the uploaded artifact to 7 days.

## Local verification

The static contract suite uses only Python's standard library:

```sh
python3 -m unittest discover -s tests -v
```

The stateful smoke is intentionally runner-only. Local verification does not pull images or create Docker resources.

## Preserved diagnostic provenance

The completed direct Docker port diagnostic remains implemented as the inactive `direct-port` script mode with its strict result profile and tests. The sole workflow does not select or expose that mode. Its prior receipt remains diagnostic history and is not containment admission evidence.
