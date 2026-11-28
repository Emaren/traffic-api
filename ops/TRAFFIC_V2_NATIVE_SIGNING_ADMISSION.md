# Traffic V2: original-Keychain production payload signing (source-only)

**State:** source and compiler checks do not authorize a public traffic day,
create an ACTIVE revocation branch, install a unit or activate a publisher.
This source must be independently reviewed before any invocation of --sign.

## Existing physical roles (never recreate, rotate, or export)

- Owner on M1: Keychain service \`aoe2war.traffic-v2.owner-ed25519.v1\`,
  account \`Emaren-github-15059910\`, public PEM SHA256
  \`1cdbfb2a532cd6fd1aea1f82f0b5fdc9865133a080d21ecda1837ffd91b91469\`.
- Classifier on M1: \`aoe2war.traffic-v2.classifier-ed25519.v1\`,
  account \`Emaren-github-15059910-classifier\`, public SHA
  \`f445fc5a38b34ae11965fd0db1d28636bb86417ba9d6a63d1ae94886c805316b\`.
- Upstream on Intel **LOCAL native console only**:
  \`aoe2war.traffic-v2.upstream-ed25519.v1\`,
  account \`Emaren-github-15059910-upstream\`, public SHA
  \`28065defa7c9c48ebde916f19a90a82409274f8ce62d8aea94a5cb39b8b743de\`.

The original enrollment utilities sign custody challenges ONLY. Do not rerun
them, claim they signed a production day, or use them to re-enroll the keys.
This new tool reads the existing Keychain item *in process*; only a detached
86-character base64url Ed25519 signature is written. It does not write raw
private-key bytes or place a Keychain password in an environment variable.

## Build and source qualification

On the M1 with Xcode CLI available, compile the **reviewed exact source**:

    /usr/bin/xcrun swiftc -O -o /private/tmp/traffic-v2-payload-signer-arm64 \
      ops/native/traffic_v2_keychain_payload_sign.swift
    /usr/bin/xcrun swiftc -O -target x86_64-apple-macosx10.15 \
      -o /private/tmp/traffic-v2-payload-signer-x86_64 \
      ops/native/traffic_v2_keychain_payload_sign.swift

Pin native binary and Swift source SHA256, execute native schema fixture tests
in \`tests/test_public_audience_v2_native_signer.py\`, and review exact source
and host byte readback before installing into an owner-private path. Intel
binary must be transferred only via the **existing pinned ordinary SSH route**
and installed in an owner-private review directory; no changes to Intel
recovery receiver, SSH keys, ciphertext, Keychain ACL or storage vault.
Test \`--validate-fixture\` without Keychain access first. No headless SSH
\`--sign\` invocation: a real unlocked local Terminal is mandatory.

## Exact signing prerequisites

**Do not sign a guessed day.** The canonical \`day\` document is precisely
\`scripts.public_audience_v2_day_admission.FIELDS\`, sorted compact UTF-8 JSON
(no trailing newline). The source-page document must pass
\`check_day_witness\` against the *same* completed UTC day and its original
source epoch, host policy and fixed snapshot/forward-prefix rowid. Require
physical root-ledger agreement, real NGINX log delivery EOF through UTC
00:31, all writer receipt clocks valid, actual global-IP classifier/cross-day
session and late-arrival digests, plus independently verified total/potential/
confirmed counts. Source-paging and a raw request count are only NECESSARY,
never a canonical audience classification. Prior UNKNOWN dates stay UNKNOWN.

Before any Keychain call, an independent operator verifies the source and
stores identical **0600 canonical payload bytes** inside the appropriate
\`~/Library/Application Support/AoE2WAR/TrafficV2SigningRequests/{role}/\`
directory, itself 0700 and owned by the existing local user. File must be
regular (not symlink) and link-count one. The exact owner-visible SHA256 is
recomputed from these bytes; any mismatch holds.

**Authority boundaries and local-console order:**

1. **Intel** (upstream): sign only that sourced, independently reviewed
   \`day\` payload with original upstream key. Preserve native detached signature.
2. **M1** (classifier): independently review same page/body/visitor rules and
   sign the *identical canonical day payload* with original classifier key.
   Compare exact input SHA256 on the two Macs. Both signatures must separately
   pass the existing \`verify_dual_witness\` and underlying original source
   finality; no shared key or owner substitute.
3. **M1** (owner): after both independent witnesses and HEL1 API/WE2 activated
   gap-renderer readbacks, prepare one <=35-day \`delegation\` scoped to exact
   production source commit, source DB dev+inode, ingestion unit source SHA,
   original upstream/classifier key SHA and historical release SHA; sign with
   original owner Keychain. Prepare and sign matching revision-one \`state\`
   with \`ACTIVE\` and the digest of the **signed delegation body**.
4. Perform separately owner-authorized, one-use initial ACTIVE genesis on the
   existing \`traffic-v2-revocation\` branch; preserve ruleset #27691195,
   required protected transition check and negative REVOKED tests. A signed
   local file is not an authoritative external ACTIVE branch.
5. WE2 source-pinned protected root installer installs reviewed merged Traffic
   V2 source, source/ledger/trust/root configuration, nonroot service and timer
   with inverse; proves exact root readback before enable. No use of traffic
   source-only PR merge as root-install authority.
6. Verify first newly certified public day in SQLite and both APIs, then
   independently observe a different day published by the **natural** timer.

## One-day owner permit (alternative to recurring delegation)

For the installed `authorization_mode=one_day`, first establish both genuine
source witnesses and verify their signatures against the exact day certificate.
Then prepare the exact `public_audience_v2_operator_permit.FIELDS` document,
including the actual certificate SHA, current public matrix preimage, source
commit, source DB dev/inode, loaded ingest unit, protected API and admitted
renderer hashes. The permit expires within 60 minutes and binds a completed
UTC day; it is not an authorization for another day or any future timer run.
Use the existing owner Keychain on M1 with `--kind permit` after native local
approval. The verifier still checks all live bindings and signature identity.
The original upstream/classifier roles, their distinct public keys, physical
local console requirement, and exact SHA confirmation remain unchanged.
This source extension does not sign or publish a day. No delegation or ACTIVE
revocation-state signature is required for a one-day permit; recurring
publication continues to require its existing separate delegation admission.

## Native command signature (only after real source and local approval)

The binary requires exactly these arguments in this fixed order:

    <reviewed-native-binary> --sign \
      --role <upstream|classifier|owner> \
      --kind <day|permit|delegation|state> \
      --input /Users/<account>/Library/Application\ Support/AoE2WAR/TrafficV2SigningRequests/<role>/<canonical-name>.json \
      --signature-output /Users/<account>/Library/Application\ Support/AoE2WAR/TrafficV2SigningRequests/<role>/<new-name>.sig \
      --approve-sha256 <actual-full-64-character-SHA256>

The binary displays role/kind/hash and waits for local human confirmation
\`APPROVE <first-16-hex> <role>\`. It rejects any SSH/non-TTY invocation,
wrong role/CPU architecture, invalid schema, noncanonical JSON, stale day,
incomplete arrival clocks, unauthorized original key, wrong public SHA,
shared/writable request directory, symlinks and output overwrite.
No role can cross-sign another role's payload.

The detached signature has 86 base64url characters with no newline. The
existing **Python** verifiers own certificate/delegation/state JSON envelopes;
do not invent new envelope or replace verifiers. Native \`--validate-fixture\`
is a schema-only test and may never be cited as authentic day certification.

**Mandatory current stop:** until original host day evidence and the actual
first/second signatures + owner ACTIVE external state and root installer are
physically verified, maintain \`FIRST_NEW_DAY=NONE\`,
\`UNATTENDED_SECOND_DAY=NONE\`, and \`ROOT_PUBLISHER=NOT_INSTALLED\`.
