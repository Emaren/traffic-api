# Traffic V2 publisher — exact, fail-closed WE2 admission

This is a **source-only package**, not an installed service or an owner's signature.
The canonical source base is traffic-api `5c9677c427f0f091c9e860ff3151f98cb3566838`.
These files add only the previously missing `traffic-v2-publisher.service`
and `traffic-v2-publisher.timer` already expected by
`public_audience_v2_production_reconciliation.py`.

## Scope and physical owner gate

WE2 owns the root-controlled source installation. Source-specific, separately
approved owner-native privilege is needed to:

1. Install the source/byte-reviewed Traffic V2 Python modules in the existing
   `/var/www/Traffic/traffic-api` deployment, **after** re-proving the live
   forward-ledger hash and reconciling the protected Git object permissions.
   Never reset the dirty running checkout or restart another production service.
2. Admit the existing three **distinct** owner/upstream/classifier public keys
   at root-owned, parent-guarded 0644 trust paths, without re-enrolling keys.
3. Construct and check root-owned 0644
   `/etc/aoe2war/traffic-v2/runner.json` with exactly
   `public_audience_v2_runner.FIELDS`. Bind the actual regular SQLite inode
   (not an unqualified symlink), source commit, live ingest unit hash, root-owned
   API source copy, and **independently observed** WE2 gap-renderer readback.
   The configured evidence/backup/checkpoint paths must be pre-created as
   0700 directories owned by the nonroot run UID; the worker lock belongs to
   the checkpoint. The service writable boundary in this source is only the
   Traffic DB directory plus a source-scoped publisher directory on DATA.
   If actual checked paths differ, revise/review the unit **before** installation.
4. Admit an independently signed real completed UTC day: exact upstream
   closed-log EOF/delivery source with finality, separate canonical classifier
   sessionization/watermark signature for the SAME day, source replay/late-arrival
   guard, and either a one-day owner permit or a revocable signed delegation.
   The external owner-signed ACTIVE state must exist at the already protected
   `traffic-v2-revocation` branch path; a 404 or stale signed state HOLDS.
5. Install *only* these exact reviewed systemd unit bytes through the existing
   privileged owner-native release controls. Verify with
   `systemd-analyze verify` and native `systemctl cat`/unit hash readback.
   Activation may happen only after all admission proofs are present.
   No implicit systemd changes are made by this source package.

The runner uses a bounded, signed completed-day append; the hourly timer's
`*:37 UTC` retry respects its 31-minute day-finality floor and handles missing
evidence fail-closed. It does **not** create upstream or classifier signatures.
The legacy `traffic-public-audience-aoe2hdbets.timer` must remain disabled.

## Production acceptance after protected activation

Use the runner's `--status` first in the separately admitted nonroot context.
Only the real host-approved installation process may start/enable the new timer.
Prove one authentic signed new day and independent SQLite/API/website equality,
then observe a **different day** published from a natural unattended timer
firing. The three public values are total traffic, potential humans, confirmed
humans. Missing dates stay UNKNOWN; never backfill forged zeroes. Preserve
the historical 131 certified days ending 2026-10-19. Public service HTTP200
and a timer being enabled alone are not day-publication evidence.

Keep WE1 financial isolation, rollback 3030, emergency 3033, and the active
Atlas release train unchanged. No new root command channel, signer/key
ceremony, receiver, archive system or storage daemon is authorized here.

Until the actual root installer receipt, signed witnesses, ACTIVE state,
first new public day and second unattended day are independently verified:
**TRAFFIC_V2_PUBLISHER_INSTALL=HOLD; FIRST_DAY=NONE; SECOND_DAY=NONE**.
