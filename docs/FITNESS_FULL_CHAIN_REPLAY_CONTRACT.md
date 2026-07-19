# Fitness full-chain replay contract

## Status and authority

This is a source contract only. It does not authorize a GitHub Actions dispatch,
a runner registration, infrastructure spend, Supabase project access, or an
application replay. The workflow is intentionally routed only to the unique
`fp-hosted-replay-jit-v1` self-hosted ephemeral label. Until a separately
reviewed JIT packet provisions that boundary, the workflow has no eligible
runner.

The adapter is stacked on the reviewed containment foundation at commit
`6901855ab62ec3d2751491558825d9270666c934`. It does not modify the generic
containment workflow, private-network-namespace probe, observer, pins, or
Supabase configuration.

## Immutable source denominator

The only admitted application source is public Git data from
`fawxzzy/fawxzzy-fitness`:

- base commit/tree `317568f9dcbc7d6c9dcf2ad30ef1cd80022ce8b3` /
  `bd4b2809a2a613a4bc67a4cc8166bee56d64a30f`;
- candidate commit/tree `4ff406c92c1d9b9e7ab23a4ebdaa01820b9b5c01` /
  `e8314980790dd9c711f63f4b38ad61e59ec6f409`;
- 101 base migrations and 102 candidate migrations;
- base chain digest
  `236ded2d260b2787838219f6e54fa63cbed80a8581930f165ca6025bca91db3a`;
- candidate chain digest
  `711445d03b3d98466c278c4dfcbaa7cda326f188427b6dbcd55065fae1a2bbb5`;
- one added candidate migration and zero historical edits.

The complete ordered path/blob/byte/raw-SHA-256 denominator is frozen in
`fitness/source-manifest.v1.json`. Before containment, the adapter fetches both
full commit IDs into a new packet-owned bare object store, proves each commit's
tree, reads every migration by exact blob ID, checks its length and SHA-256, and
materializes only the 102 root migration files. Moving refs, archives,
checkouts, symlinks, nested paths, duplicates, missing files, and extras are
rejected. The object store and staged sources are removed during exact cleanup.

## Replay boundary

The JIT runtime is a separate prerequisite, not an implicit privilege grant. It
must expose exactly:

- the label `fp-hosted-replay-jit-v1` on a one-job ephemeral runner;
- `/run/fp-hosted-replay-jit-v1/docker.sock`, never the host Docker socket or a
  TCP API;
- `/run/fp-hosted-replay-jit-v1/observer.sock`, backed only by that private
  daemon and enforcing the reviewed one-shot `foundation-db-start-v1` policy;
- the exact pinned adjacent `supabase` and `supabase-go` binaries;
- a self-digested, closed-schema runtime attestation proving an exclusive
  packet VM, an exclusive private daemon, no provider credentials, and a
  network-closed container boundary.

The adapter has no host-socket fallback. It creates one exact internal Docker
network through the trusted host executor. The pinned Supabase CLI `v2.109.1`
receives only the policy-observer socket, not the private daemon socket, and
uses the reviewed no-source configuration. The host executor accepts one
database container only when its exact project label, one-network attachment,
and zero host publication are proven. All SQL is streamed with `docker exec
-i` by the trusted packet executor; no host database listener or database URI
is used.

No source or target project ref, access token, API key, JWT, password, linked
state, Auth identity, provider credential, remote database URL, or real user
data is admitted. The CLI is local-only and the container boundary has no
default route. Fixed external DNS, literal-IP, metadata, host, and registry
attempts must execute and fail closed.

## Ordered replay and controlled fixture boundary

Migrations 1 through 101 are applied in manifest order. The deterministic
synthetic fixture is then created before migration 102 because the accepted
base history intentionally reserves human member number `0`, while migration
102 prevents caller-selected identities. The fixture contains only:

- humans `human-000` through `human-005`, mapped to numbers `0` through `5`;
- automation `automation-000`, whose member number and assignment timestamp are
  null;
- fixed synthetic UUIDs with no email, Discord identity, or external account.

Migration 102 is then applied exactly once as the candidate-chain delta. The
adapter records all 102 ordinal/path/digest/duration records. Re-executing its
SQL later is an explicit idempotency probe and is not recorded as a second
chain application.

The proof deletes `human-003` and requires that only its mapping disappears and
number `3` remains a gap. Eight fixed synthetic humans are inserted through
eight simultaneous database sessions. Every insert must succeed, numbers must
be distinct and strictly above the prior high-water mark, the automation row
must remain null, and the effective next sequence value must remain above the
post-insert high-water mark.

The mapping digest is SHA-256 over canonical JSON rows sorted by synthetic
label. Each row contains only label, `user_kind`, member-number-or-null, and an
assignment-timestamp-present boolean. UUIDs are never included.

## Immutability, privilege, and idempotency gates

The replay requires:

- same-value identity updates succeed;
- changes to `user_number`, `user_kind`, and
  `user_number_assigned_at` fail;
- `PUBLIC`, `anon`, and `authenticated` have no sequence privileges;
- `service_role` has SELECT and neither USAGE nor UPDATE;
- direct `nextval` as `anon` and direct `setval` as `authenticated` fail;
- function and trigger state digests are unchanged by the migration-102
  idempotency probe;
- the final mapping digest is unchanged by the idempotency probe.

Any missing, ambiguous, malformed, unexpectedly successful, or unexpectedly
failed proof blocks the run.

## Receipt and cleanup

Only `artifacts/fitness-full-chain-replay.json` may be uploaded. The closed
schema permits immutable source identities, synthetic labels, aggregate counts,
ranges, booleans, timings, object-state digests, ordered migration paths and
digests, containment results, and residue denominators. It rejects unknown
keys, duplicate JSON keys, oversized/control-bearing values, emails, JWT-like
values, database URIs, profile/user IDs, raw request bodies, and raw logs. The
receipt is self-digested.

Cleanup is exact and label/identity bounded. It removes only the admitted
project's containers and volumes plus the packet-labeled network, then proves
zero packet containers, volumes, networks, listeners, staged-source entries,
and runtime residue. The private daemon is attested exclusive to the packet VM;
there is no broad host cleanup. The always-run recovery path repeats these
queries, preserves a valid PASS only when cleanup remains exact, and otherwise
publishes BLOCKED evidence. VM exit alone is never cleanup proof.

## Workflow governance and held gates

`.github/workflows/fitness-full-chain-replay.yml` is manual-only, grants only
`contents: read`, has no inherited secrets, uses pinned checkout and artifact
actions, disables concurrency cancellation, limits the job to 30 minutes, and
retains the sanitized artifact for seven days. The dispatch SHA is passed into
the adapter and must equal the checked-out full head.

Execution remains held until all of the following are separately admitted:

1. a reviewed JIT infrastructure packet provisions the exact label, socket,
   pinned binaries/images, attestation, network boundary, teardown supervisor,
   and spend ceiling;
2. the final adapter head receives dedicated control-plane review;
3. a single exact-head workflow dispatch is explicitly authorized;
4. any potentially chargeable action receives fresh `FP-MAN-025` approval with
   current scope, quote, budget, and maximum.

A passing replay proves only the disposable synthetic Fitness chain. It does
not authorize a target bootstrap, provider mutation, source-project retirement,
production deployment, or merge.
