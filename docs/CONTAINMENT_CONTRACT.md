# Containment contract

## Authority boundary

`FP-HOSTED-REPLAY-CONTAINMENT-SMOKE-001` owns only resources correlated by the packet label or the Supabase project label `fp-hosted-replay-ro-001`. Cleanup never prunes and never enumerates foreign resources for deletion.

No application repository, application migration, source data, Auth row, provider API, Supabase remote command, production environment, secret, or inherited workflow environment is in scope.

## Ordered gates

1. Verify Ubuntu 24.04, x86_64, Docker client/server `>=28`, at least 8 GiB actual RAM, and more than 10 GiB free disk. The exact hosted image is retained in GitHub's **Set up job** log.
2. Download the one pinned CLI asset and verify SHA-256 before extraction.
3. Pull exactly two `linux/amd64` Docker digest references, verify platform/RepoDigests/image IDs, and retag them to the CLI's public-ECR lookup names.
4. Reject the fixed subnet if it overlaps a host link route or existing Docker network.
5. Create one internal IPv4 bridge with IPv6 disabled, loopback default binding, isolated IPv4 gateway mode, fixed subnet, and packet labels.
6. Prove the isolated bridge has no host IPv4 address. On the exact network, prove no default route, failed external DNS, failed `1.1.1.1:443`, failed metadata access, and failed host/gateway reachability.
7. Freeze the unique network name to its exact Docker engine ID, then pass that name to the pinned CLI because v2.109.1 treats `--network-id` as a user-defined network name. Re-prove the name-to-ID mapping, labels, options, subnet, scope, and zero prestart endpoints immediately before CLI start.
8. Immediately before CLI execution, require zero exact database containers, zero exact database volumes, and no listener on 56422. Freeze only the counts and SHA-256 of normalized listener tuples on native ports 5432 and 5433; never connect to, stop, or otherwise mutate those listeners. Require the native fingerprints to remain unchanged after CLI exit and after cleanup.
9. Observe sanitized Docker `create` and `start` phases. At every observed phase, re-prove the frozen network contract and require the container's sole attached network to carry the exact frozen engine ID. Require exactly one database create/start pair and exactly one `gotrue migrate` create/start pair; reject create-without-start, any second correlated network, or network drift.
10. Freeze an event-history boundary after the last empty-network proof. After CLI exit, query only project-labelled container create/start/die/destroy events, project-labelled volume-create events, and connect events for the exact frozen network within that boundary. Reduce the transient history to action counts, set digests of hashed object identities, pinned-image correlation, frozen-network correlation, nonzero-exit counts, and one allowlisted classification. Raw events, names, IDs, labels, timestamps, and messages never enter state or the artifact.
11. Require one reported publication: `127.0.0.1:56422`, plus a successful loopback TCP connection.
12. Require `pg_cron` and `pg_net`, a non-empty Auth schema table count, zero successful direct pg_net egress results, and zero successful external results from one pg_cron-guarded pg_net request.
13. Remove only correlated containers, volumes, networks, and scratch. Require zero correlated resources and no listener on 56422.

## Fail-closed result

Every failure maps to a stable uppercase code, and later pre-cleanup or cleanup evidence cannot overwrite the first explicit failure code. A reachable daemon-reported packet gateway is `PACKET_GATEWAY_REACHABLE`. A non-unique or drifting network name-to-ID mapping is `NETWORK_NAME_ID_MAPPING_FAILED`; a created packet container with no matching start phase is `CONTAINER_CREATED_NOT_STARTED`. Supabase database start is bounded to 300 seconds and maps immediately to `SUPABASE_DB_START_TIMEOUT` before post-start Docker reads. Before any DB-start failure mapping, the transient CLI log is reduced to only its exit code, match count, optional first-match line number, byte count, line count, SHA-256, and one deterministic allowlisted category: `CONFIG_VALIDATION_FAILED`, `CLI_USAGE_ERROR`, `IMAGE_RESOLUTION_FAILED`, `NETWORK_CONFIGURATION_REJECTED`, `VOLUME_PREPARATION_FAILED`, `CONTAINER_CREATE_FAILED`, `CONTAINER_START_FAILED`, `PORT_BIND_FAILED`, `DATABASE_HEALTH_FAILED`, `GOTRUE_MIGRATION_FAILED`, `DOCKER_DAEMON_ERROR`, or `UNKNOWN_SANITIZED`. Exact v2.109.1 wrappers for volume parsing/creation and Docker container creation/start are covered explicitly.

Historical create/start identities must equal the live observer's hashed create/start identities. A mismatch is `OBSERVER_COVERAGE_GAP`; volume creation without container creation is `CONTAINER_CREATE_FAILED`; create without start is `CONTAINER_CREATED_NOT_STARTED`; a nonzero database or GoTrue exit maps to `DATABASE_HEALTH_FAILED` or `GOTRUE_MIGRATION_FAILED`. A more specific transient-log category may refine a start failure to `CONTAINER_START_FAILED` or `PORT_BIND_FAILED`. Image or frozen-network correlation failure stops independently. The raw CLI message and raw event history are never copied into state or the artifact. Watcher shutdown is bounded to five seconds, and each exact container, volume, and network removal is independently bounded to 20 seconds. An explicit `if: always()` cleanup-only step reuses the exact packet filters, verifies zero resources and listeners, and merges only sanitized cleanup counts into the receipt before upload. Raw command output remains transient and is never uploaded. A failed gate does not cause a broader network, another runner label, an unpinned image, a remote Supabase path, or an application replay.

## Network-name compatibility contract

The pinned CLI places `--network-id` into Docker network mode and calls `NetworkCreate` using that value as a user-defined network name. The source-compatible contract therefore passes the unique pre-created name, while the harness independently freezes and continuously validates the exact engine ID. This supersedes literal engine-ID flag usage without weakening any network property. Any additional packet/project-labelled network is rejected and exact cleanup remains ID-correlated.

## Direct Docker port diagnostic

`FP-HOSTED-REPLAY-DIRECT-PORT-DIAG-001` remains an inactive, preserved diagnostic-only script mode. The manual workflow does not select or expose it. It does not download or invoke the Supabase CLI, execute SQL, or run an application migration. It preserves the runner, subnet, isolated-network, bridge, and prestart no-egress gates above, then pulls only the pinned `linux/amd64` Postgres digest and creates one target container with `--pull=never`.

The target requests `56422:5432` without a HostIp. The network's `com.docker.network.bridge.host_binding_ipv4=127.0.0.1` option must cause Docker's observed binding to be exactly one `127.0.0.1:56422` entry. A generated workflow-local database password is masked before it enters the container through an environment-name-only Docker argument, then unset. The diagnostic never requests `Config.Env`, emits container environment, executes SQL, or retains the password. A packet-owned tmpfs replaces the image data volume, so no database volume or data survives cleanup.

The allowlisted inspection rejects host/extra networks, privilege, host PID or IPC namespaces, devices, added capabilities, security options, extra hosts, bind mounts, Docker socket access, an unexpected tmpfs/mount, any explicit HostIp request, any non-loopback or second observed binding, and any restart or OOM. Health must remain stable for 10 seconds. Loopback TCP must connect; every deterministically discoverable non-loopback host IPv4 address must fail. Absence of a testable non-loopback address is reported as a zero tested count, while the exact Docker binding remains mandatory.

Only `fawxzzy.hosted-replay-harness.direct-port-result.v1` is publishable for this mode. Its allowlist is packet, terminal status/failure code, hashed image/network/container identities, binding class/counts, health/restart/OOM state, timings, and cleanup counts. Raw Docker output, health logs, container IDs, image IDs, network IDs, credentials, environment, SQL, connection material, JWTs, and keys remain transient or are never read. `DIRECT_DOCKER_PORT_PATH_PASS` proves only this direct Docker/network/port path; it does not admit Supabase CLI startup or application replay.
