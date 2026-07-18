# Containment contract

## Authority boundary

`FP-HOSTED-REPLAY-CONTAINMENT-SMOKE-001` owns only resources correlated by the packet label or the Supabase project label `fp-hosted-replay-ro-001`. Cleanup never prunes and never enumerates foreign resources for deletion.

No application repository, application migration, source data, Auth row, provider API, Supabase remote command, production environment, secret, or inherited workflow environment is in scope.

## Current status-only diagnostic

The manual workflow's fixed default mode is `status-phase-split-v1`. It invokes only the pinned CLI's `supabase status --ignore-health-check` command after the preserved runner, image, network, canary, listener, and empty-object gates. It never invokes `db start`, `db reset`, migrations, SQL, GoTrue, or any application/provider path. A clean status exit proves no replay admission.

Only the status child receives the packet-local `DOCKER_HOST`. The observer permits `GET` and `HEAD` only. Any other method is counted as one write attempt, stopped before its bytes reach the Docker daemon, and classified `DOCKER_API_WRITE_ATTEMPT_OBSERVED`. Read-only traffic remains byte-transparent. Raw status output may contain generated local keys, so it is created under process umask `077`, reduced only to command exit, byte/line counts, and SHA-256, and deleted before any phase decision.

Zero observer connections and requests maps to `SHARED_INIT_BLOCKED_BEFORE_DOCKER_API`. One or more successful, fully answered `CONTAINER_LIST` requests, optionally preceded by read-only API negotiation, maps to `DB_START_SPECIFIC_PRE_API_BLOCKER`. Any other phase, non-2xx response, incomplete response, unknown path, write attempt, object event, or listener/network drift blocks without claiming a phase split.

## Ordered status-diagnostic gates

1. Verify Ubuntu 24.04, x86_64, Docker client/server `>=28`, at least 8 GiB actual RAM, and more than 10 GiB free disk. The exact hosted image is retained in GitHub's **Set up job** log.
2. Download the one pinned CLI asset and verify SHA-256 before extraction.
3. Pull exactly two `linux/amd64` Docker digest references, verify platform/RepoDigests/image IDs, and retag them to the CLI's public-ECR lookup names.
4. Reject the fixed subnet if it overlaps a host link route or existing Docker network.
5. Create one internal IPv4 bridge with IPv6 disabled, loopback default binding, isolated IPv4 gateway mode, fixed subnet, and packet labels.
6. Prove the isolated bridge has no host IPv4 address. On the exact network, prove no default route, failed external DNS, failed `1.1.1.1:443`, failed metadata access, and failed host/gateway reachability.
7. Freeze the unique network name to its exact Docker engine ID, then pass that name to the pinned CLI because v2.109.1 treats `--network-id` as a user-defined network name. Re-prove the name-to-ID mapping, labels, options, subnet, scope, and zero prestart endpoints immediately before CLI start.
8. Immediately before CLI execution, require zero exact database containers, zero exact database volumes, and no listener on 56422. Capture each listener snapshot as explicit command-precheck, query, normalization, count, hash, and sanitized-record operations, with stable begin/complete phases around every operation. Freeze only operation exit codes, normalized counts, and SHA-256 of normalized listener tuples on native ports 5432 and 5433; never connect to, stop, or otherwise mutate those listeners. Require the native fingerprints to remain unchanged after CLI exit and after cleanup.
9. Start the existing container lifecycle watcher and the permissions-restricted Docker API observer, then invoke exactly one status-only child. Require zero write attempts and allow only API negotiation plus `CONTAINER_LIST` read phases.
10. Freeze event history after the last empty-network proof. After status exit, require zero project-labelled container create/start/die/destroy events, zero project-labelled volume-create events, zero exact-network connect events, and zero watcher observations. Raw events remain transient.
11. Re-prove the frozen network and native listener fingerprints, then remove only correlated resources and scratch. Require zero correlated containers, volumes, networks, and no listener on 56422.

## Inactive containment-admission gates

Database/GoTrue create/start, loopback publication, extension availability, Auth schema, pg_net, and pg_cron checks remain preserved below the terminal status-phase decision in the runner, but are unreachable in `status-phase-split-v1`. They are not evidence from this packet and cannot be used to admit application replay.

## Fail-closed result

Every failure maps to a stable uppercase code, and later pre-cleanup or cleanup evidence cannot overwrite the first explicit failure code. A reachable daemon-reported packet gateway is `PACKET_GATEWAY_REACHABLE`; a non-unique or drifting network name-to-ID mapping is `NETWORK_NAME_ID_MAPPING_FAILED`. The prior database-start fingerprint remains historical evidence only and is not reproduced because this packet cannot invoke database start.

The sanitizer's output schema is closed: only fixed dotted keys, scalar types, uppercase enums, booleans, nonnegative integers, and a 64-character lowercase SHA-256 are admitted. Credential-bearing URLs, JWTs, bearer tokens, password/secret/token/key assignments, connection strings, private keys, environment dumps, SQL, Auth rows, PII, and arbitrary text can never be values in the sanitized state. Secret-shaped input is counted only as a boolean and line count; its content is never retained.

For the Docker API boundary diagnostic, only the pinned Supabase CLI child receives a packet-local `DOCKER_HOST` that targets a permissions-restricted Unix-socket observer. Every harness Docker command continues to use the real daemon socket directly. The observer relays allowed read-only bytes unchanged and parses only bounded HTTP framing as a side channel. API-version prefixes are discarded and request targets are immediately reduced to fixed phase enums. Query values, headers, bodies, identifiers, names, labels, mounts, commands, socket paths, and raw traffic are never retained or emitted. A prohibited method is reduced to its method class and phase, counted, and terminated before upstream forwarding.

The observer receipt contains only its fixed schema and classification, connection/request/response/error counts, first/last/error phase enums, allowlisted method/status counters, and a canonical SHA-256 over those sanitized fields. Multiple requests on reused connections, fixed-length and chunked framing, partial reads, and concurrent connections must remain byte-transparent. Any parser, upstream, forwarding, response-completeness, permission, shutdown, or schema failure blocks the packet. The observer socket and readiness marker are removed on shutdown; its sanitized state is merged into the receipt and packet scratch is deleted before closeout.

Listener diagnostics map unavailable tooling, a nonzero query, normalization failure, count failure, hash failure, and sanitized receipt failure to `LISTENER_COMMAND_UNAVAILABLE`, `LISTENER_QUERY_NONZERO`, `LISTENER_NORMALIZATION_FAILED`, `LISTENER_COUNT_FAILED`, `LISTENER_HASH_FAILED`, and `LISTENER_RECEIPT_WRITE_FAILED`. An otherwise preterminal exit between `PRE_CLI_BOUNDARY_BEGIN` and `PRE_CLI_PREFLIGHT_COMPLETE` maps to `LISTENER_UNEXPECTED_INTERRUPTION` with only the last stable phase. Raw listener output and normalized tuples remain transient and are deleted with scratch; addresses, process details, and tuples never enter logs, state, receipts, or artifacts. Local initialization is split defensively without attributing the prior interruption to initialization behavior.

For this status-only packet, any lifecycle or event-history observation is `STATUS_DOCKER_MUTATION_OBSERVED` or `STATUS_CONTAINER_LIFECYCLE_OBSERVED`; no create/start identity is accepted. Image or frozen-network correlation failure stops independently. Watcher shutdown is bounded to five seconds, and each exact container, volume, and network removal is independently bounded to 20 seconds. An explicit `if: always()` cleanup-only step reuses the exact packet filters, verifies zero resources and listeners, and merges only sanitized cleanup counts into the receipt before upload. Raw command output remains transient and is never uploaded. A failed gate does not cause a broader network, another runner label, an unpinned image, a remote Supabase path, or an application replay.

## Network-name compatibility contract

The pinned CLI places `--network-id` into Docker network mode and calls `NetworkCreate` using that value as a user-defined network name. The source-compatible contract therefore passes the unique pre-created name, while the harness independently freezes and continuously validates the exact engine ID. This supersedes literal engine-ID flag usage without weakening any network property. Any additional packet/project-labelled network is rejected and exact cleanup remains ID-correlated.

## Direct Docker port diagnostic

`FP-HOSTED-REPLAY-DIRECT-PORT-DIAG-001` remains an inactive, preserved diagnostic-only script mode. The manual workflow does not select or expose it. It does not download or invoke the Supabase CLI, execute SQL, or run an application migration. It preserves the runner, subnet, isolated-network, bridge, and prestart no-egress gates above, then pulls only the pinned `linux/amd64` Postgres digest and creates one target container with `--pull=never`.

The target requests `56422:5432` without a HostIp. The network's `com.docker.network.bridge.host_binding_ipv4=127.0.0.1` option must cause Docker's observed binding to be exactly one `127.0.0.1:56422` entry. A generated workflow-local database password is masked before it enters the container through an environment-name-only Docker argument, then unset. The diagnostic never requests `Config.Env`, emits container environment, executes SQL, or retains the password. A packet-owned tmpfs replaces the image data volume, so no database volume or data survives cleanup.

The allowlisted inspection rejects host/extra networks, privilege, host PID or IPC namespaces, devices, added capabilities, security options, extra hosts, bind mounts, Docker socket access, an unexpected tmpfs/mount, any explicit HostIp request, any non-loopback or second observed binding, and any restart or OOM. Health must remain stable for 10 seconds. Loopback TCP must connect; every deterministically discoverable non-loopback host IPv4 address must fail. Absence of a testable non-loopback address is reported as a zero tested count, while the exact Docker binding remains mandatory.

Only `fawxzzy.hosted-replay-harness.direct-port-result.v1` is publishable for this mode. Its allowlist is packet, terminal status/failure code, hashed image/network/container identities, binding class/counts, health/restart/OOM state, timings, and cleanup counts. Raw Docker output, health logs, container IDs, image IDs, network IDs, credentials, environment, SQL, connection material, JWTs, and keys remain transient or are never read. `DIRECT_DOCKER_PORT_PATH_PASS` proves only this direct Docker/network/port path; it does not admit Supabase CLI startup or application replay.
