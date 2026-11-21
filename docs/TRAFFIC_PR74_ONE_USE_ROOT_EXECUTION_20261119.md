# WE2 — Traffic #74 one-file protected root executor

**2026-11-19 status: candidate source ONLY. This is not an installed root tool, owner signature, trust enrollment or physical postimage.**

## Fixed scope

This companion to Traffic PR #74 implements only the original reviewed 56 bytes:

\`\`\`ini
[Service]
Environment=TRAFFIC_INGEST_RECEIPTS_ENABLED=1
\`\`\`

Target (original preimage ABSENT): \`/etc/systemd/system/traffic-ingest.service.d/90-traffic-v2-insertion-receipts-only.conf\`. SHA256: \`f9a50e57fad5d9f562cafc2b89dde9c7e403f48300d5833871168ab03fc879fe\`. Original full systemctl-cat digest: \`97b7b6341e17c4b2a90ccadf3c9b42140180443ed53d808c6dcc600c72c56f40\`; *predicted* postimage digest: \`1a700eacf9e0494706fbe32111db890a33f7f620592fdfc17ec071ae6781bea9\`. Physical verification after root action is mandatory; do not confuse the predicted digest with installed state.

The source-controlled executable is \`scripts/traffic_pr74_onefile_executor.py\`. Once **separately source-admitted** and installed, the sole fixed executable path is \`/usr/local/libexec/aoe2war/traffic_pr74_onefile_executor.py\`, root-owned, not group-writable. It accepts only \`--phase install\` or \`--phase inverse\`. No file path, SQL, systemd unit, ExecStart, script, or arbitrary command input exists. It never starts an extra writer or restarts Traffic/website/Steam.

## Legitimate one-use owner trust — not automatically created

An accepted, source-reviewed protected **root enrollment** must first install this fixed executable and:

- root:root 0700 \`/etc/aoe2war/traffic-pr74/\`, containing exact root-owned \`allowed_signers\`, \`install.json\`, \`install.sig\`, and fresh \`we4_preinstall_witness.json\`;
- root:root 0700 \`/var/lib/aoe2war-traffic-pr74/\` for exclusive lock, consumed nonce and durable postimage/inverse receipts;
- a separately authorized owner public key **specific to Traffic #74**, named principal \`aoe2war-traffic-pr74-owner\`, SSH signature namespace \`aoe2war-traffic-pr74\`.

The root executor verifies owner SSH signature over **the exact bytes** of the manifest, rather than a GitHub comment, an unsigned request, a reused Factory/PRODUCT signer, C08 authority, a generic root SSH session, or a broad sudo rule. This source PR is not an enrollment and cannot supply an owner's private signature.

Required *exact* JSON fields: \`schema\` = \`aoe2war.traffic.pr74.one-use-maintenance.v1\`; \`purpose\` = \`TRAFFIC_PR74_RECEIPT_SETTING_ONLY\`; \`action\` = \`install\` (or distinct \`inverse\`); \`target\`; \`source_sha\` = \`6ec52fd7c82ed9f2e536badf56f4f5b1b788b293\`; \`executor_sha256\` = the reviewed **actually installed** root program byte hash; \`dropin_sha256\`; \`original_unit_sha256\`; \`postimage_sha256\`; \`witness_sha256\`; unique 64-hex \`nonce\`; integer \`issued_at_unix\` and \`expires_at_unix\` no more than 900s apart; and \`financial_authorized\` exactly false. All unknown fields, drift, replay, stale timestamps and wrong action are denied. The inverse needs its own separately signed one-use permit.

WE4 must supply a genuinely fresh (<=90 seconds) root-owned read-only witness, which the owner signature binds by hash. The witness includes original SQLite device+inode, \`MAX(rowid)\`, last 1,000 actual insertion-stamp count, NGINX device+inode and \`traffic_ingest_state\` inode+offset. Root verifies the witness against an immediate new WAL-aware read-only SQLite/NGINX measurement, not a historical R0.

Before committing its sole hardcoded file, the executor validates eight source digests, original full systemd fingerprints, original 2-minute timer, single \`flock\` writer, API no-inline-ingestion, Steam V27 success, stable Kingdom MainPID, closed 8092–8095, and held financial services. It consumes a root-owned nonce *before* installation. The exact drop-in is written, fsynced, atomically linked, followed by \`systemctl daemon-reload\` and actual source/loaded-environment/fingerprint verification. An automatic **exact-digest-only** inverse is attempted on a failed install; any drift holds. Successful action creates a durable fsynced, root-private receipt. It does not backfill old NULL insertion timestamps.

After that, WE4 must witness a **natural** timer-triggered new rowid with real non-NULL \`ingested_at_utc\`, compare original NGINX evidence and confirm historical rows untouched, before calling ingestion instrumentation PASS. No 2-day certification, external revocation or daily audience publisher is admitted by this file.

## Hard operational stopline

Previously the remote root execution channel denied a protected install. **Do not bypass that denial** with another command channel or generic owner sudo. If the source-bound owner root enrollment, exact one-use signed permit, fresh WE4 witness or independent protected install acceptance is not actually present, return HOLD. This PR provides testable source and negative tests, not production authority. Keep original 131 certified public days and financial C03 HOLD intact.
