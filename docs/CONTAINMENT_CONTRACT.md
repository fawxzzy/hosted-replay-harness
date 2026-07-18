# Containment contract

## Authority boundary

`FP-HOSTED-REPLAY-CONTAINMENT-SMOKE-001` owns only resources correlated by the packet label or the Supabase project label `fp-hosted-replay-ro-001`. Cleanup never prunes and never enumerates foreign resources for deletion.

No application repository, application migration, source data, Auth row, provider API, Supabase remote command, production environment, secret, or inherited workflow environment is in scope.

## Current root-initialization diagnostic

The manual workflow's fixed default mode is `root-init-split-v1`. It invokes exactly `supabase telemetry status` from the pinned v2.109.1 binary. It never invokes local `status`, `start`, `stop`, `db start`, `db reset`, login/link, remote flags, migrations, SQL, GoTrue, an application path, image acquisition, or Docker lifecycle mutation. The workflow-selected `run` path terminates before the preserved inactive image/network/direct-diagnostic code.

The immutable source contract is finite:

- `apps/cli-go/cmd/root.go` defines the root `PersistentPreRunE` that loads the profile, resolves the current project working directory, parses database-related flags when present, prepares local telemetry context, and initializes Sentry.
- `apps/cli-go/cmd/telemetry.go` defines the `telemetry status` leaf with `RunE`; neither that file nor `internal/telemetry` calls `flags.LoadConfig` or Docker.
- `apps/cli-go/go.mod` pins Cobra v1.10.2. Cobra executes the first inherited `PersistentPreRunE` before a runnable leaf's `RunE`, so this leaf provably crosses root persistent initialization. Help and version shortcuts are not used.
- `DO_NOT_TRACK=1` and `SUPABASE_TELEMETRY_DISABLED=1` prevent telemetry capture. `SUPABASE_HOME` is packet-local. A fresh packet-local `supabase/.temp/cli-latest` is pre-seeded with the pinned version so the post-command upgrade check reads locally instead of contacting GitHub.

Only the root-init child receives packet-local `HOME`, `SUPABASE_HOME`, all four XDG roots, `TMPDIR`, and `DOCKER_HOST`; its environment is rebuilt with `env -i`. The Docker observer permits `GET` and `HEAD` only, but this command must produce zero connections and requests. Any request, write method, forwarding/parser error, packet object, or listener delta is `BLOCKED_UNKNOWN` or a narrower fail-closed boundary code.

Raw CLI output is created under umask `077`, reduced to exit code, byte/line counts, SHA-256, and two exact fingerprint-match booleans, then deleted. The child starts inside a packet-local project-root sentinel so root initialization does not emit a machine-specific workdir path. Scratch files are reduced to the closed classes `PROJECT_ROOT_SENTINEL`, `CLI_UPDATE_CACHE`, and `TELEMETRY_STATE`, per-class counts, and a canonical digest. Any other file class is `ROOT_INIT_STATE_ESCAPE`. All scratch is deleted before the terminal classification.

## Ordered root-init gates

1. Verify Ubuntu 24.04, x86_64, Docker client/server `>=28`, at least 8 GiB actual RAM, and more than 10 GiB free disk.
2. Download the one pinned CLI asset, verify its SHA-256, extract it, and verify the frozen binary SHA-256. The CLI `--version` shortcut is not executed because the pinned source makes it perform an external upgrade lookup.
3. Require zero packet-labelled/project-labelled containers, volumes, and networks; no listener on 56422; and frozen count/digest fingerprints for native listeners 5432 and 5433.
4. Create only permissions-restricted packet scratch and pre-seed only the local upgrade-cache class.
5. Start the read-only Docker API observer, then invoke exactly one root-only child with all supported mutable locations redirected and telemetry endpoint delivery disabled.
6. Stop the observer deterministically. Require zero connections, requests, responses, write attempts, forwarding errors, and parser errors.
7. Sanitize and delete raw output, audit the closed scratch classes, and delete all root-init scratch.
8. Re-prove zero packet objects, no 56422 listener, and unchanged native listener fingerprints.
9. The explicit `if: always()` cleanup step proves zero correlated containers, volumes, networks, listeners, bytecode, and runtime scratch before the sanitized artifact is retained.

## Terminal split

- Exit `0` with the exact source-derived `Telemetry is enabled.` fingerprint and zero Docker API traffic records `diagnostic.classification=ROOT_INIT_PASS` and terminates with `LOAD_CONFIG_BLOCKER`. Root persistent initialization passed; the remaining shared failure boundary is `flags.LoadConfig`.
- Exit `1` with the exact prior `1,078`-byte, `23`-line, `d3a19bac...` fingerprint and zero Docker API traffic terminates `ROOT_PERSISTENT_INIT_BLOCKER`.
- Any other output, command exit, Docker request, state escape, object/listener drift, observer failure, or cleanup ambiguity terminates `BLOCKED_UNKNOWN` or its narrower stable prerequisite code.

These are diagnostic classifications only. None admits containment, database startup, GoTrue migration, or application replay.

## Fail-closed result

Every failure maps to a stable uppercase code, and cleanup evidence cannot overwrite the first explicit failure code. The prior database-start/status fingerprint is admitted only as the exact root-persistent comparison fingerprint; the packet cannot invoke either command that originally produced it.

The sanitizer's output schema is closed: only fixed dotted keys, scalar types, uppercase enums, booleans, nonnegative integers, and a 64-character lowercase SHA-256 are admitted. Credential-bearing URLs, JWTs, bearer tokens, password/secret/token/key assignments, connection strings, private keys, environment dumps, SQL, Auth rows, PII, and arbitrary text can never be values in the sanitized state. Secret-shaped input is counted only as a boolean and line count; its content is never retained.

For the Docker API boundary diagnostic, only the pinned Supabase CLI child receives a packet-local `DOCKER_HOST` that targets a permissions-restricted Unix-socket observer. Every harness Docker command continues to use the real daemon socket directly. The observer relays allowed read-only bytes unchanged and parses only bounded HTTP framing as a side channel. API-version prefixes are discarded and request targets are immediately reduced to fixed phase enums. Query values, headers, bodies, identifiers, names, labels, mounts, commands, socket paths, and raw traffic are never retained or emitted. A prohibited method is reduced to its method class and phase, counted, and terminated before upstream forwarding.

The observer receipt contains only its fixed schema and classification, connection/request/response/error counts, first/last/error phase enums, allowlisted method/status counters, and a canonical SHA-256 over those sanitized fields. Multiple requests on reused connections, fixed-length and chunked framing, partial reads, and concurrent connections must remain byte-transparent. Any parser, upstream, forwarding, response-completeness, permission, shutdown, or schema failure blocks the packet. The observer socket and readiness marker are removed on shutdown; its sanitized state is merged into the receipt and packet scratch is deleted before closeout.

Listener diagnostics map unavailable tooling, a nonzero query, normalization failure, count failure, hash failure, and sanitized receipt failure to `LISTENER_COMMAND_UNAVAILABLE`, `LISTENER_QUERY_NONZERO`, `LISTENER_NORMALIZATION_FAILED`, `LISTENER_COUNT_FAILED`, `LISTENER_HASH_FAILED`, and `LISTENER_RECEIPT_WRITE_FAILED`. An otherwise preterminal exit between `PRE_CLI_BOUNDARY_BEGIN` and `PRE_CLI_PREFLIGHT_COMPLETE` maps to `LISTENER_UNEXPECTED_INTERRUPTION` with only the last stable phase. Raw listener output and normalized tuples remain transient and are deleted with scratch; addresses, process details, and tuples never enter logs, state, receipts, or artifacts. Local initialization is split defensively without attributing the prior interruption to initialization behavior.

For this root-init packet, any Docker API request or correlated object/listener delta is terminal; no create/start identity is accepted. Observer shutdown is bounded to five seconds, and each exact container, volume, and network removal remains independently bounded to 20 seconds. An explicit `if: always()` cleanup-only step reuses the exact packet filters, verifies zero resources and listeners, and merges only sanitized cleanup counts into the receipt before upload. Raw command output and state remain transient and are never uploaded. A failed gate does not cause image acquisition, a network mutation, a remote Supabase path, or an application replay.

## Network-name compatibility contract

The pinned CLI places `--network-id` into Docker network mode and calls `NetworkCreate` using that value as a user-defined network name. The source-compatible contract therefore passes the unique pre-created name, while the harness independently freezes and continuously validates the exact engine ID. This supersedes literal engine-ID flag usage without weakening any network property. Any additional packet/project-labelled network is rejected and exact cleanup remains ID-correlated.

## Direct Docker port diagnostic

`FP-HOSTED-REPLAY-DIRECT-PORT-DIAG-001` remains an inactive, preserved diagnostic-only script mode. The manual workflow does not select or expose it. It does not download or invoke the Supabase CLI, execute SQL, or run an application migration. It preserves the runner, subnet, isolated-network, bridge, and prestart no-egress gates above, then pulls only the pinned `linux/amd64` Postgres digest and creates one target container with `--pull=never`.

The target requests `56422:5432` without a HostIp. The network's `com.docker.network.bridge.host_binding_ipv4=127.0.0.1` option must cause Docker's observed binding to be exactly one `127.0.0.1:56422` entry. A generated workflow-local database password is masked before it enters the container through an environment-name-only Docker argument, then unset. The diagnostic never requests `Config.Env`, emits container environment, executes SQL, or retains the password. A packet-owned tmpfs replaces the image data volume, so no database volume or data survives cleanup.

The allowlisted inspection rejects host/extra networks, privilege, host PID or IPC namespaces, devices, added capabilities, security options, extra hosts, bind mounts, Docker socket access, an unexpected tmpfs/mount, any explicit HostIp request, any non-loopback or second observed binding, and any restart or OOM. Health must remain stable for 10 seconds. Loopback TCP must connect; every deterministically discoverable non-loopback host IPv4 address must fail. Absence of a testable non-loopback address is reported as a zero tested count, while the exact Docker binding remains mandatory.

Only `fawxzzy.hosted-replay-harness.direct-port-result.v1` is publishable for this mode. Its allowlist is packet, terminal status/failure code, hashed image/network/container identities, binding class/counts, health/restart/OOM state, timings, and cleanup counts. Raw Docker output, health logs, container IDs, image IDs, network IDs, credentials, environment, SQL, connection material, JWTs, and keys remain transient or are never read. `DIRECT_DOCKER_PORT_PATH_PASS` proves only this direct Docker/network/port path; it does not admit Supabase CLI startup or application replay.
