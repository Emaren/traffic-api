# Public audience V2: bounded shadow pass-one checkpoint

Status: EXPERIMENTAL, NOT PUBLISHABLE. Incident: https://github.com/Emaren/traffic-api/issues/10

scripts/public_audience_v2_checkpoint.py reads exactly the canonical first-pass source filters and normalizer, but splits the scan into bounded keyset batches. All progress and host/IP request statistics, direct-referrer counts, distinct UAs and distinct paths are stored in an isolated 0600 SQLite checkpoint. Cursor and statistics are committed atomically. A frozen source max-rowid, source inode, project host set, visibility rules and canonical source file SHA are bound to the checkpoint. Late appended rows are excluded until a new source epoch.

The script has two actions: status (read-only) and advance (writes ONLY the private checkpoint). It NEVER writes the public archive, does not publish scores, and does not activate, restart or replace any systemd timer. The operator-disabled two-hour legacy forge must remain disabled.

This is the FIRST canonical pass ONLY. It does not yet calculate cross-day sessions, collapse bursts, materialize final IP behavior, or publish daily audience statistics. It also does not independently prove that existing SQLite rows are immutable between steps, nor does it handle host/visibility/source rewinds. An empty/full-history pass-one result is not sufficient to certify accuracy or enable payouts or publication.

Next engineering gates: bounded pass-two with durable session and burst-window state; compare exact classification against reference full forge on adversarial fixtures; canonical source immutability and late arrival invalidation; 18M+ scale tests under resource budgets; shadow publication/atomic checksum review; operator-authorized activation of a NEW bounded scheduler; separate public archive freshness checks. No live production execution has been performed by this PR.

Developer-only test: python -m unittest tests.test_public_audience_v2_checkpoint -v
