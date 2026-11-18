# WE4 to WE2 — Traffic V2 root installation and inverse contract
Date: November 18, 2026. This is a reviewed-source PROPOSAL, not a root permit or live install. Original Emaren/traffic-api only, stacked PR #76 → #75 → #73; independent PR #74 ingress setting. WE2 exclusively controls HEL1 installation, protected service and root operator approvals.

## Signed daily delegation extension

The root-pinned alternative authorization_mode=delegation is specified in TRAFFIC_V2_WE4_DAILY_DELEGATION_CONTRACT_20261118.md. Its separate signed ACTIVE/REVOKED state and <=35-day owner scope are not day-specific owner permits; separate independent per-day source and classifier signatures remain mandatory. The new root-config delegation paths must be admitted before unattended timer activation. Root-only signed revocation-state monotonic anti-rollback acceptance remains outstanding.

## Production-bound entrypoint
python3 -m scripts.public_audience_v2_runner --status
python3 -m scripts.public_audience_v2_runner --once

There is NO user-selectable config, source, key, approval, reset or installation option. The ONLY runtime config is /etc/aoe2war/traffic-v2/runner.json, an immutable root-owned 0644 file with root-owned immutable non-service-writable ancestor paths and exact schema traffic.public-audience.v2.root-runner.v1. The process must be a **non-root** UID/GID pinned by WE2 in that config, not root. The current restricted UID650 source CLI exits2 with HOLD_ROOT_OWNED_RUNNER_NOT_INSTALLED and zero writes.

Each invocation handles at most seven genuinely signed completed UTC days, with a 90-second bounded source-check window. Under the existing original Traffic private .canary.lock exclusive flock, the runner proves the real source DB dev/inode, accepted root-owned API source bytes, WE2 Factory gap-aware renderer activation readback, actual loaded systemctl cat traffic-ingest.service SHA, actual Environment=TRAFFIC_INGEST_RECEIPTS_ENABLED=1 and active timer. Before every append it checks current systemd again. It checks #75 finished keyset page, real source watermark and a single-row indexed query for any backdated arrival beyond that prefix; any hit halts publication. The existing independent upstream delivery and canonical classifier source signatures, plus a separately signed one-day owner permit, are verified. The original 131-day SHA and current public matrix CAS remain fixed. The existing atomic publisher runs one SQLite BEGIN IMMEDIATE, protected public preimage 0600/fsync, new day and signed certificate in the SAME COMMIT. Failure rolls both back; same-certificate replay refuses a second write.

The private certificate ledger, preimage and exact signed source are checked on every restart. A lost sidecar after a successful DB commit is reconstructed from the original source certificate+signed evidence+exact backup and current rows, with NO second public insert. No partial current UTC day, unknown historical zeros, raw request-IP human classification, second ingestion writer or new website runtime is permitted.

## Root-only trust and runtime identity

Root installer must pin all config fields: source_database; source_dev/source_inode from actual stat; project aoe2hdbets; exact reviewed source_commit_sha; current traffic_api_file plus sha256; actual WE2 website_gap_receipt with schema aoe2war.traffic-v2.gap-renderer-readback.v1, WE2_ACTIVATED_GAP_RENDERER_READBACK, Factory renderer sha and commit; exact current ingest_unit_sha256; trusted Ed25519 public keys and SHA pins for upstream, classifier and owner operator; approved run_uid/run_gid; max_days_per_run 1..7; and existing shared canary worker_lock in checkpoint_dir. The three public keys must be DIFFERENT, root-owned 0644 and outside service-writable directories. Private signing keys must NEVER be on the publisher, in Git, config, browser or logs.

Private evidence_dir, backup_dir and checkpoint_dir must exist as 0700 owned by the admitted non-root service identity. Signed evidence/YYYY-MM-DD/ contains 0600, single-hardlink, non-symlink day-envelope.json, page-state.json, owner-permit.json with file and type caps. Source DB remains the SAME existing canonical nonfinancial Traffic database. The new service identity requires only existing DB writer ACL scoped to the canonical public tables and signed certificate ledger; do not broaden other writer roles. WE2 must separately prove its actual DB ACLs and protected service constraints. The runner reads no financial DB.

## Additive day-certificate table — installation is NOT automatic
Exactly the reviewed SQL from scripts/public_audience_v2_daily_append.py, not a silent application startup migration:

    CREATE TABLE traffic_public_audience_day_certificates_v2(
      project_slug TEXT NOT NULL,
      bucket_day TEXT NOT NULL,
      certificate_sha256 TEXT NOT NULL,
      source_page_sha256 TEXT NOT NULL,
      signed_finality_schema TEXT NOT NULL,
      certified_at_utc TEXT NOT NULL,
      PRIMARY KEY(project_slug,bucket_day)
    );

Only WE2 may install after WAL-consistent backup and independent exact schema review, with physical postimage and inverse. Do not DROP the table after a successful publication merely to roll back code.

## Systemd templates — placeholders, do NOT install verbatim

    # traffic-v2-publisher.service
    [Unit]
    Description=AoE2WAR Traffic V2 independently certified daily append
    After=traffic-ingest.service
    ConditionPathExists=/etc/aoe2war/traffic-v2/runner.json
    [Service]
    Type=oneshot
    User=<WE2_accepted_nonroot_identity>
    Group=<WE2_accepted_nonroot_group>
    WorkingDirectory=<exact_root_owned_reviewed_traffic_source_release>
    ExecStart=/usr/bin/python3 -m scripts.public_audience_v2_runner --once
    Environment=PYTHONUNBUFFERED=1
    UMask=0077
    NoNewPrivileges=yes
    PrivateTmp=yes
    PrivateDevices=yes
    ProtectSystem=strict
    ProtectHome=yes
    ProtectKernelTunables=yes
    RestrictSUIDSGID=yes
    LockPersonality=yes
    ReadWritePaths=<exact_original_traffic_sqlite_parent> <exact_private_v2_state_dir>
    TimeoutStartSec=120
    MemoryMax=384M
    Restart=no

    # traffic-v2-publisher.timer
    [Unit]
    Description=Bounded signed completed-day Traffic V2 publication
    [Timer]
    OnCalendar=hourly
    Persistent=true
    RandomizedDelaySec=5m
    Unit=traffic-v2-publisher.service
    [Install]
    WantedBy=timers.target

These are NONINSTALLABLE templates. WE2 must generate exact source/protected service bytes, independent review, physical readback and a separate owner-signed permit before installation. The once-per-hour timer is enough to catch up seven signed days/run after downtime, without massive rebuilds. A missing witness returns exit2/HOLD and no writes, so no fake daily timer-success.

## Proven current HEL1 preimage (read-only, last WE2 witness)
Original root-owned /etc/systemd/system/traffic-ingest.service SHA256 ae9a923682906032343b96fb33c62ab61ed3a40c20e5d4755a78cddbb83dbac9. Actual systemctl cat traffic-ingest.service SHA256 97b7b6341e17c4b2a90ccadf3c9b42140180443ed53d808c6dcc600c72c56f40. Only PYTHONUNBUFFERED=1 loaded; no inserted-receipt flag. PR #74 proposed drop-in SHA f9a50e57fad5d9f562cafc2b89dde9c7e403f48300d5833871168ab03fc879fe; predicted loaded SHA 1a700eacf9e0494706fbe32111db890a33f7f620592fdfc17ec071ae6781bea9 (PREDICTED ONLY, NOT INSTALLED). Independent B/Steam protected postimage acceptance and owner root permit remain absent.

WE2's bounded Oct20/Nov15/Nov16/Nov17 sample found 2048/2048 SOURCE rows with NULL insertion times, not proof that every historical row lacks receipts. On Nov8 202 authentic receipts occurred during a short prior test, then reverted due Steam fingerprint drift. This does NOT prove a full UTC day complete. Actual last certified day Oct19 2026; public Traffic API and website API 131 identical rows, Oct19 Total/Potential/Confirmed 10695/615/283. Oct20–Nov17 are 29 genuinely UNKNOWN days. No real signer keys or day evidence have been admitted.

## Required actual physical acceptance sequence
1. WE2 recovers immutable protected NGINX rotations, upstream source bytes/inodes and EOF/offset delivery receipts. A file mtime or request timestamp is not an insertion clock. Independent upstream closure must cover the whole UTC day plus 31-minute session-expiry margin; source offsets, receipt clocks and no late arrival must match.
2. WE2 and independent C03/Steam reviewers admit/install only the exact one-writer PR #74 change, read actual systemctl cat and effective loaded Environment, test genuine natural insertion clocks. Keep original timer, no second source writer, retain C04 masks and financial port isolation.
3. Use #75 bounded source paging and forward ledger with original canonical global-IP/UA/path, bot logic and cross-midnight 30-minute sessions. Independently prove session/parity and two consecutive COMPLETE real UTC days. Upstream and canonical classifier sign true source-bound evidence with separately held keys. No fabricated historical arrival clock or zero-filled gap.
4. WE2 proves /traffic can represent missing UTC days as explicit gaps while preserving chart layout/colors/axes/legend/hover. Install actual Factory gap renderer readback and source-bound Traffic API hash. Do not connect Oct19 visually to a future day across missing days.
5. Only then install owner-key trust/one-day permit, exact source commit, additive certificate ledger and private files/ACLs; run --status, then --once under the admitted nonroot process with the original .canary.lock. Independently verify two actual days, restart/no duplicate, late arrival HOLD, crash after commit recovery and positive signed public API/website/browser date parity.
6. WE2 enables hourly timer after authentic repeated physical acceptance. Run until latest independently complete UTC day; output source receipt sample date and full-day unknown date set. The timer must NOT re-enable the old 18M-row full-history audience forge.

## Inverse and rollback
Rollback is first disable ONLY the newly installed traffic-v2-publisher.timer/oneshot and remove its exact root-managed unit/config under a separate reviewed inverse. Keep already certified public day rows, signed ledger, preimages, WAL, source history and original 131 days intact. Never delete public rows or rewrite earlier insertion timestamps to reset a failed release; authorize any correction separately. Verify traffic-ingest.timer, original Steam protected unit, C03/financial isolation and public API old/new dates after rollback. WE2 root alone signs and performs operations.

## Current acceptance scoreboard
New genuine source UTC days: 0/2. Production publisher installed: NO. Canonical newest public day: 2026-10-19. Unknown Oct20–Nov17: 29 dates. Source runner and root-admission contract: SOURCE ONLY. No site UI or HEL1 root modification from WE4. Source and tests must be admitted with exact GitHub HEAD CI plus real human independent reviewer, not author acceptance.
