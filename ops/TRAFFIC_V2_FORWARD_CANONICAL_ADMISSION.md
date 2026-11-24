# WE4 forward canonical pass-two — private source admission

This source-only change provides a bounded, read-only canonical forward
classifier candidate and repairs private forward observer compatibility
with genuine future certificate-backed public additions. It adds no new
signer, publisher, service, financial access, or historical data.

## Preserve the exact frozen canonical source

Do not edit scripts/rebuild_public_audience_archive.py. Its SHA256 must be
1b389839428a2453fa870dfb2f2661087b386b5c5f22782b45de6e6cfe12c321,
pinned by the historical source checkpoint. New code invokes the original
stream_sessions, normalize_row, build_single_session, and finalize_bucket
inside one isolated read-only CLI process. The original merged_ip_behavior
combines historical and private forward IP-count/UA/path behavior without
new visitor classification thresholds.

## Source-only candidate and hard STOP

Execute scripts/public_audience_v2_forward_canonical_candidate.py only
through the existing independent WE2 root source-read authorization.
Original sealed private historical checkpoint, forward ledger, and private
IP shadow must be 0600 regular files in one existing private directory.
The original source identity must match the historical checkpoint.
The forward cursor must cover the source high-water observation and the
IP shadow must have processed exactly the private forward accepted rows.
The adapter reconstructs canonical timestamp/line_offset/rowid order
from the ledger's original RAW_FIELDS. It requires two preceding-day
replay windows to agree on the target-day metrics and enforces bounded
event/time memory constraints.

Example source contract, after WE2 identifies the real existing private
IP-shadow path and installs exact-reviewed source:

    cd /home/tony/AoE2WAR-Recovery/EXACT_REVIEWED_SOURCE_STAGE
    python3 -B -m scripts.public_audience_v2_forward_canonical_candidate \
      --source /mnt/HC_Volume_105319120/traffic-db/traffic_history.sqlite3 \
      --historical /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/checkpoint.sqlite3 \
      --ledger /mnt/HC_Volume_105319120/traffic-v2-shadow/canary-oocB0WuA/future-ledger.sqlite3 \
      --shadow "$WE2_APPROVED_EXISTING_PRIVATE_IP_SHADOW_PATH" \
      --day 2026-11-23 --max-events 6000000 --budget-seconds 600

The CLI ALWAYS exits 2. The private output is intentionally a
nonpublishable candidate, even when the three candidate metrics agree
across two windows. It must NEVER be interpreted as a certificate.

## Independent actual day finality

The independent upstream must prove original NGINX live/rotated log EOF
and writer insertion receipts closed at least 31 minutes after the UTC
day ends. The existing original source paging contract must exhaust
that same root-pinned forward prefix with zero missing insertion clocks
and prove late-arrival stability. Classifier independently compares
source-equivalent global-IP behavior, canonical cross-midnight session
classification, three metrics and source/model digests.

Only a real completed-day report with all these verified components may
be serialized into existing day_admission.FIELDS using sorted compact
UTF-8 canonical JSON. Have Intel upstream and M1 classifier independently
review and locally sign IDENTICAL exact-hash payloads with the already
merged original-Keychain native signer. Synthetic fixtures, custody-only
attestation signatures, and invented counters are never acceptable.

Owner M1 subsequently signs the original <=35-day delegation and ACTIVE
state with authentic verified root/site preimages; the latter must be
admitted via protected external ruleset #27691195. WE2 then installs
the already merged root configuration and nonroot publisher service
and timer through its independent protected root permit. Prove first
new day and second NATURAL unattended timer-backed publication via both
public Traffic and website APIs. Unknown gaps remain UNKNOWN.

## Future certified public rows

The private forward observer now checks the immutable historical 131-day
digest separately from later dates. Every later row requires a matching,
well-shaped entry in the reviewed V2 day certificate ledger, so a genuine
132nd public row cannot stall subsequent private capture. This is an
additional observer consistency check, NOT a replacement for verifying
the original dual Ed25519 signatures in the publisher. Missing later
dates need no placeholders or zeroes, and unsigned/historical tampering
remains denied.

Do not alter WE1, Atlas, root services, protected vaults, existing Intel
recoveries, any signing identity or public SQL from this source PR alone.
