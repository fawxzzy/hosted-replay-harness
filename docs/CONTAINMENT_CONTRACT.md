# Containment contract

## Authority boundary

`FP-HOSTED-REPLAY-CONTAINMENT-SMOKE-001` owns only resources correlated by the packet label or the Supabase project label `fp-hosted-replay-ro-001`. Cleanup never prunes and never enumerates foreign resources for deletion.

No application repository, application migration, source data, Auth row, provider API, Supabase remote command, production environment, secret, or inherited workflow environment is in scope.

## Current stateful DB-start policy

The manual workflow has one fixed `run` path. It invokes the pinned v2.109.1 CLI exactly once as `supabase --workdir <packet-project> --network-id <frozen-name> --yes db start`. The public config remains byte-frozen at SHA-256 `1b955c23161259dd41f3849f261bab41525b5ffeca83ab3074e44c5cc18ac0c6`; database migrations and seed are disabled, Auth is enabled only for its one-shot migration, and every other persistent service is disabled.

The earlier loader diagnostic proved `Config.Load` succeeds under a fresh child environment. Database start therefore uses the same `env -i` boundary: fixed system `PATH`, packet-local `HOME`, XDG roots and `TMPDIR`, `DO_NOT_TRACK=1`, and child-only `DOCKER_HOST`. It inherits no `SUPABASE_*`, CI, runner home/config, linked state, credential, provider, or application value. The local CLI upgrade cache is pre-seeded with the pinned version.

The v2.109.1 Linux asset is an exact adjacent two-member closure. Before extraction, the loader parses raw tar headers and requires only the unique root regular `0755` entries `supabase` (`109,918,528` bytes; SHA-256 `e9c1c33233b4341a0475f9acb2ecac35c41f6c9aa6cfdcd4f54b3761cc789c20`) and `supabase-go` (`100,909,240` bytes; SHA-256 `d10d8059b90d9fd68a69cb808b88dd3fe9f57ec458ffefc79a83083b3e810616`) in that order. Nested, duplicate, link, device, FIFO, socket, PAX, long-name, sparse, special-bit, owner/group, padding, or extra entries fail closed. Both payloads must be ELF64 little-endian x86-64, are extracted adjacently at mode `0555`, and are rehashed before any Docker pull or prestart gate. The receipt retains only their public hashes, sizes, member-manifest and adjacency digests; `SUPABASE_GO_BINARY` remains unset.

The transient DB-start classifier is source-pinned and has exactly four outcomes: `CLI_USAGE_ERROR`, `CONFIG_LOAD_OR_VALIDATION_FAILED`, `DOCKER_CLIENT_INITIALIZATION_FAILED`, and `UNKNOWN_SANITIZED`. It strips only well-formed ANSI SGR sequences. TAB, LF, and CR are the only admitted controls; malformed escapes, OSC/DCS, NUL, other C0/C1 controls, and invalid UTF-8 fail closed to `UNKNOWN_SANITIZED`. Exact Cobra v1.10.2 and pflag v1.0.10 dispatch phrases, exact Config.Load read/merge/decode/traversal/validation prefixes, and the two exact Supabase Docker-client initialization wrappers are the only matching families. Cross-family matches, sensitive-shaped input, and near matches stay unknown.

The receipt retains only raw byte/line counts and SHA-256, normalization status, SGR and rejected-control counts, matched-family count, optional first-match line, and whether the raw metadata equals the accepted recurring fingerprint. The fingerprint (`1,078` bytes, `23` lines, SHA-256 `d3a19bac055dc3fad0bca48c92d3cbe3d1d59ec9ac43d90829b5dd0c41545d31`) establishes recurrence only and can never select a category. Normalized or matched text is never emitted or retained, and the raw file is deleted before artifact construction.

The Docker observer remains read-only when no policy descriptor is supplied. DB start is admitted only by a private one-shot `fawxzzy.hosted-replay-harness.db-start-policy.v1` descriptor. The harness creates it with mode `0600`, passes it to the observer on an inherited descriptor, unlinks the path, and closes the harness copy before starting the CLI child. The descriptor contains only frozen public identities plus a fresh nonce. It never reaches the CLI child, and observer generation other than zero terminates `POLICY_LEDGER_LOST` rather than resuming state.

The admitted endpoint denominator is the source-proven 47-row matrix with SHA-256 `9669ebd4ae75cfdc3950c9db8b2786270023ce0e26dde993806b3f7b6b2c5492`: 18 child lifecycle rows, 17 prohibited rows, and 12 outer-harness rows, with zero endpoint unknowns. Optional `/vX.Y` prefixes must exactly equal the daemon version negotiated by `/_ping`.

The child sequence is single-use and ordered:

1. `HEAD /_ping`, with the source-conditional `GET` fallback only.
2. Exact database-container and volume inspection returning 404.
3. Exact cached PostgreSQL image inspection returning the frozen image ID.
4. An exact-name network reuse probe returning 409; a 201 network creation is a policy violation.
5. Exact labelled database-volume create, database-container create and start.
6. One through 121 exact identity/network/port health inspections. Only the failure branch may read non-following database logs.
7. Exact cached GoTrue image inspection and exact-name network reuse probe returning 409.
8. Exact one-shot GoTrue create and start, one following log stream, exit-code-zero inspect, and exact force-plus-volume removal.

Every returned container ID is recorded only in the observer's private transient ledger, hashed for the receipt, and consumed once. The policy rejects order changes, replay, ID substitution, name/label/image/digest/network/port drift, unknown fields, image pull, actual network creation, broad list or cleanup, privilege, host/PID/IPC mode, Docker socket, devices, capabilities, security options, extra binds/ports/networks, exec, attach, archive, wait, kill, build, prune, malformed framing, oversized content, concurrency, and restart recovery. The database may have only its exact volume, exact packet network, and requested `5432/tcp -> 56422`; observed publication must be exactly `127.0.0.1:56422`. GoTrue may run only `gotrue migrate`, with no bind or publication.

## Ordered containment gates

1. Verify Ubuntu 24.04, x86_64, Docker client/server `>=28`, at least 8 GiB actual RAM, and more than 10 GiB free disk.
2. Download and verify the pinned CLI asset, parse its exact two-member tar denominator, and verify both adjacent executable payloads before Docker access. Pull only the frozen `linux/amd64` PostgreSQL and GoTrue digests, verify RepoDigests, platforms and image IDs, then retag only to the CLI-expected aliases.
3. Create one labelled fixed-subnet bridge with `Internal=true`, IPv6 disabled, loopback host binding and isolated gateway mode; freeze its exact engine ID while passing only its unique name through `--network-id`.
4. Prove no default route and failure of external DNS, literal `1.1.1.1`, metadata, gateway, and host reachability on that exact network.
5. Require zero packet database containers/volumes and no 56422 listener, freeze native 5432/5433 count/digests, start the watcher and policy observer, then invoke DB start once under the clean environment.
6. Stop both observers deterministically, classify and delete raw CLI output, delete child scratch, and require a complete policy ledger with zero violations, unknown phases, image pulls, broad lists, cleanup calls, parser errors, or forwarding errors.
7. Correlate live observations with bounded daemon history; require exactly one database create/start and one GoTrue create/start on the frozen network and pinned images.
8. Require the database healthy at the sole loopback publication, GoTrue migration success, and `pg_cron` plus `pg_net` availability. Bounded DNS/literal-IP `pg_net` requests and a one-shot `pg_cron` external canary must have zero external success.
9. Exact label/ID cleanup must leave zero packet containers, volumes, networks and 56422 listeners, with native 5432/5433 fingerprints unchanged. The explicit `if: always()` cleanup step repeats the zero-residue proof before the sanitized artifact is retained.

## Fail-closed result

Every failure maps to a stable uppercase code, and cleanup evidence cannot overwrite the first explicit failure code. The accepted database-start fingerprint is correlation metadata only: it cannot select or promote a classifier category.

The sanitizer's output schema is closed: only fixed dotted keys, scalar types, uppercase enums, booleans, nonnegative integers, and a 64-character lowercase SHA-256 are admitted. Credential-bearing URLs, JWTs, bearer tokens, password/secret/token/key assignments, connection strings, private keys, environment dumps, SQL, Auth rows, PII, and arbitrary text can never be values in the sanitized state. Secret-shaped input is counted only as a boolean and line count; its content is never retained.

Only the pinned Supabase CLI child receives the packet-local `DOCKER_HOST`; every harness Docker command continues to use the real daemon socket. The observer relays only policy-admitted bytes unchanged and parses bounded HTTP framing as a side channel. API-version prefixes are validated then normalized, and request targets are immediately reduced to fixed phase enums. Query values, headers, bodies, identifiers, names, labels, mounts, commands, socket paths, and raw traffic are never retained or emitted. In default mode every non-read method is stopped before upstream forwarding. In DB-start mode, a write is forwarded only after exact body, identity, order, and ledger predicates pass; any unknown or malformed request is stopped and reduced to one closed policy code.

The observer receipt contains only its fixed schema and classification, connection/request/response/error counts, first/last/error phase enums, allowlisted method/status counters, and a canonical SHA-256 over those sanitized fields. Multiple requests on reused connections, fixed-length and chunked framing, partial reads, and concurrent connections must remain byte-transparent. Any parser, upstream, forwarding, response-completeness, permission, shutdown, or schema failure blocks the packet. The observer socket and readiness marker are removed on shutdown; its sanitized state is merged into the receipt and packet scratch is deleted before closeout.

Listener diagnostics map unavailable tooling, a nonzero query, normalization failure, count failure, hash failure, and sanitized receipt failure to `LISTENER_COMMAND_UNAVAILABLE`, `LISTENER_QUERY_NONZERO`, `LISTENER_NORMALIZATION_FAILED`, `LISTENER_COUNT_FAILED`, `LISTENER_HASH_FAILED`, and `LISTENER_RECEIPT_WRITE_FAILED`. An otherwise preterminal exit between `PRE_CLI_BOUNDARY_BEGIN` and `PRE_CLI_PREFLIGHT_COMPLETE` maps to `LISTENER_UNEXPECTED_INTERRUPTION` with only the last stable phase. Raw listener output and normalized tuples remain transient and are deleted with scratch; addresses, process details, and tuples never enter logs, state, receipts, or artifacts. Local initialization is split defensively without attributing the prior interruption to initialization behavior.

Observer shutdown is bounded to five seconds, and each exact container, volume, and network removal remains independently bounded to 20 seconds. An explicit `if: always()` cleanup-only step reuses the exact packet filters, verifies zero resources and listeners, and merges only sanitized cleanup counts into the receipt before upload. Raw command output, descriptor material, dynamic credentials, connection values, SQL bodies, and scratch state remain transient and are never uploaded. Any failed policy or containment gate terminates without a retry, weakened network, remote Supabase path, or application replay.

## Network-name compatibility contract

The pinned CLI places `--network-id` into Docker network mode and calls `NetworkCreate` using that value as a user-defined network name. The source-compatible contract therefore passes the unique pre-created name, while the harness independently freezes and continuously validates the exact engine ID. This supersedes literal engine-ID flag usage without weakening any network property. Any additional packet/project-labelled network is rejected and exact cleanup remains ID-correlated.

## Direct Docker port diagnostic

`FP-HOSTED-REPLAY-DIRECT-PORT-DIAG-001` remains an inactive, preserved diagnostic-only script mode. The manual workflow does not select or expose it. It does not download or invoke the Supabase CLI, execute SQL, or run an application migration. It preserves the runner, subnet, isolated-network, bridge, and prestart no-egress gates above, then pulls only the pinned `linux/amd64` Postgres digest and creates one target container with `--pull=never`.

The target requests `56422:5432` without a HostIp. The network's `com.docker.network.bridge.host_binding_ipv4=127.0.0.1` option must cause Docker's observed binding to be exactly one `127.0.0.1:56422` entry. A generated workflow-local database password is masked before it enters the container through an environment-name-only Docker argument, then unset. The diagnostic never requests `Config.Env`, emits container environment, executes SQL, or retains the password. A packet-owned tmpfs replaces the image data volume, so no database volume or data survives cleanup.

The allowlisted inspection rejects host/extra networks, privilege, host PID or IPC namespaces, devices, added capabilities, security options, extra hosts, bind mounts, Docker socket access, an unexpected tmpfs/mount, any explicit HostIp request, any non-loopback or second observed binding, and any restart or OOM. Health must remain stable for 10 seconds. Loopback TCP must connect; every deterministically discoverable non-loopback host IPv4 address must fail. Absence of a testable non-loopback address is reported as a zero tested count, while the exact Docker binding remains mandatory.

Only `fawxzzy.hosted-replay-harness.direct-port-result.v1` is publishable for this mode. Its allowlist is packet, terminal status/failure code, hashed image/network/container identities, binding class/counts, health/restart/OOM state, timings, and cleanup counts. Raw Docker output, health logs, container IDs, image IDs, network IDs, credentials, environment, SQL, connection material, JWTs, and keys remain transient or are never read. `DIRECT_DOCKER_PORT_PATH_PASS` proves only this direct Docker/network/port path; it does not admit Supabase CLI startup or application replay.
