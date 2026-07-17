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
7. Start `supabase db start` with the actual Docker network ID. A concurrent observer inspects only non-environment Docker fields and stops any correlated container that violates the network, privilege, namespace, device, capability, mount, image, command, or port contract.
8. Require exactly one database observation and exactly one `gotrue migrate` observation. Reject a second correlated network.
9. Require one reported publication: `127.0.0.1:56422`, plus a successful loopback TCP connection.
10. Require `pg_cron` and `pg_net`, a non-empty Auth schema table count, zero successful direct pg_net egress results, and zero successful external results from one pg_cron-guarded pg_net request.
11. Remove only correlated containers, volumes, networks, and scratch. Require zero correlated resources and no listener on 56422.

## Fail-closed result

Every failure maps to a stable uppercase code. A reachable daemon-reported packet gateway is `PACKET_GATEWAY_REACHABLE`. Supabase database start is bounded to 300 seconds and maps immediately to `SUPABASE_DB_START_TIMEOUT` before post-start inspection. Watcher shutdown is bounded to five seconds, and each exact container, volume, and network removal is independently bounded to 20 seconds. An explicit `if: always()` cleanup-only step reuses the exact packet filters, verifies zero resources and listeners, and merges only sanitized cleanup counts into the receipt before upload. Raw command output remains transient and is never uploaded. A failed gate does not cause a broader network, another runner label, an unpinned image, a remote Supabase path, or an application replay.

## Known compatibility probe

The pinned CLI treats `--network-id` as Docker network mode but also attempts `NetworkCreate` and tolerates only a Docker conflict. This harness deliberately passes the actual ID as required and then asserts the correlated network count remains exactly one. If the daemon creates a second network whose name is the first network's ID, the terminal result is `CLI_CREATED_SECOND_NETWORK` and both correlated networks are removed by exact ID.
