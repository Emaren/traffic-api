# C03: Traffic forward ledger — offline systemd finance-network boundary

**Status: source candidate; financial gate HOLD.** This is nonfinancial
hardening of the private Traffic V2 canary forward-ledger worker. It does not
assert that Traffic is permanently excluded from the HD/DE/WOLO writer universe
and it cannot close C03 or authorize any Wolo Satchel operation.

## Why this service was not finance-qualified

The installed HEL1 unit `traffic-v2-forward-ledger-aoe2hdbets.service`
previously used `User=root`, all 41 effective Linux bounding capabilities,
including `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, and `CAP_NET_ADMIN`,
and had no isolated IP network. `NoNewPrivileges=yes` and
`ProtectSystem=strict` alone were not enough to prove it could not interact
with HD/DE/WOLO financial systems. Its active timer fires every five minutes.
The exact installed baseline file SHA256 was
`ed2a08928daaa44105b236efb00f66101a8347e98674c2110c4ebc0eba0a4f1a`.
The source repository is `Emaren/traffic-api` at
`60cf4da5962b4ba65f546d2bea68c3cdc03e8479`.

The current private canary directory and checkpoint/ledger databases are
root-owned, mode `0700` and `0600`; a straight `User=tony` change
would break that existing workload. The source Traffic database directory is
`tony:tony` mode `0775`; the worker keeps `User=root` for its private
canary and uses `Group=tony` to permit SQLite WAL/SHM coordination without
CAP_DAC_OVERRIDE. A native read-only run with `Group=root` and zero caps
failed `OperationalError: attempt to write a readonly database`, while the
identical sandbox with `Group=tony` returned `mode=READ_ONLY`,
`source_verified=true`, `publish_authorized=false` (exit 0). The hardening does **not** silently
change ownership, 1.6 GB ledger files, historic 50 GB source Traffic DB,
or maintenance behavior.

## Source-bound minimal sandbox

`ops/systemd/traffic-v2-forward-ledger-aoe2hdbets.service` adds:

- `PrivateNetwork=yes`: separate network namespace; no host TCP route
- `RestrictAddressFamilies=AF_UNIX`: cannot create AF_INET/AF_INET6
- Empty `CapabilityBoundingSet=` and `AmbientCapabilities=`: no CAP_SYS_ADMIN,
  CAP_DAC_OVERRIDE, CAP_NET_ADMIN, or other ambient/effective caps
- `InaccessiblePaths=-/run/postgresql -/var/run/postgresql`: mask standard
  PostgreSQL Unix socket directory even though AF_UNIX is permitted
- `RestrictNamespaces=yes`, protected kernel tunables/modules/cgroups,
  `LockPersonality=yes`, `RestrictSUIDSGID=yes`
- Existing `NoNewPrivileges=yes`, `ProtectSystem=strict`, private tmp,
  `UMask=0077`, exact two Traffic writable directories and source SQLite
  read-only mounts remain unchanged

These are not a substitute for reviewing every possible AF_UNIX service
socket, all future unit/drop-in changes, the Python modules actually imported,
or the complete HD/DE/WOLO writer permissions. Continued root UID is a
transitional risk requiring an eventual narrow unprivileged file-ownership
migration and repeated negative proof. No fake second human reviewer exists;
the user is the sole financial owner.

## Tests and release constraints

`tests/test_c03_forward_ledger_offline_systemd_boundary.py` checks the
exact systemd unit configuration and fails on new network families, restored
capabilities, renamed executable, additional writable mounts, extra commands,
new environment files and loss of PostgreSQL socket masking.

On HEL1, an independently created **transient, disposable systemd unit**
reproduced the proposed settings without modifying/restarting the installed
Traffic service. The physical probe returned:

`PASS_C03_TRANSIENT_FINANCE_NETWORK_AND_CAPABILITY_DENIAL`

It observed `inet_socket_denied=true`, `effective_caps_zero=true`,
`bounding_caps_zero=true`, `no_new_privs=true`,
`postgres_data_write_open_denied=true`,
`postgres_socket_directory_inaccessible=true`,
`traffic_source_file_readable=true`. No actual finance DB or WOLO mutation
was attempted, and no financial release was authorized.

**Physical promotion remains HOLD** until exact-source full CI and a
same-property compatibility exercise on copied SQLite data, negative checks
for host PostgreSQL and WOLO HTTP endpoints, fresh unit identity/override
checks, rollback and Traffic heartbeat/freshness comparison. Only the current
private SQLite ledger job may be admitted; an unrelated Traffic API, ingest,
cron, Docker, new unit or authenticated database session is a separate writer
candidate.

This narrow unit patch does not start funded Satchel 8094/8095, migrate
finance schema, change database role grants, close any C01–C09 gate,
or replay an UNKNOWN payment. The owner-only C09 transaction permit remains
distinct from this source hardening.
