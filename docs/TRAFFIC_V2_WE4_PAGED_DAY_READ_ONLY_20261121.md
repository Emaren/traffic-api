# WE4 Traffic V2 — Bounded paged UTC-day insertion evidence, source only

Date: November 21, 2026. This is a **read-only pre-certification
source witness**, not a daily audience certificate or publisher permit.
This work does not alter the installed Traffic v2 ingestion service,
its single-writer flock, forward-ledger, root runner or website.

The historical 131 certified days remain immutable, ending October 19,
2026. October 20 through November 20 remain UNKNOWN without real
independent signed delivery/classifier evidence and protected authority.
A raw count of 430,484 November 20 multi-host requests is not a count
of real players, visitors or canonical sessions.

## Source-backed change

The preexisting Traffic day evidence script retains its default
maximum 20,000 rows, 45-second maximum and fail-closed response.
A separately selected --paged-source-only mode pages up to 20,000
candidates at a time. It uses the same original source SQLite
read-only transaction, exact frozen checkpoint, source inode/device,
canonical host set, original nonbrowser filter, required
timestamp/line-offset index, and forward-ledger pin.

Keyset continuation is ordered by timestamp, line_offset and rowid.
Each selected page produces a SHA-256 digest and SHA-256 hashes
of its first/last key, without writing private visitor metadata to
public files. One-row lookahead proves each page boundary. A
missing terminal page, invalid key, duplicate rowid, NULL or invalid
UTC insertion clock, known frozen-history retroactive input, mismatched
source forward prefix, host drift, missing index, unavailable worker
priority, source/budget mismatch or time expiry holds the operation.
Offset-based pagination, source writes and sample-only completeness
inference are forbidden.

PAGED ceiling: max 60 pages, max 600,000 candidate source rows,
180-second end-to-end read-only work budget. Values are caps, not
targets. Runs should use the existing guarded idle/lock only during
approved low-priority source audit windows; an over-budget day is a
HOLD pending independent source engineering, not a license to infer
zero or drop events.

## Evidence and explicit limits

Source-only SQL fixture tests verify the 20,000-row page boundary
using 20,015 synthetic timestamped events, repeated event timestamps
and offsets resolved by rowid, missing insertion receipts across page
boundaries, page-limit exhaustion, read-only source byte parity,
retained legacy single-page refusal, and source time/page caps.

PAGED can assert that the exact **local** read-only snapshot's
eligible canonical-filtered rows were scanned through its final
page under a bounded source row budget. It cannot assert that an
independent upstream NGINX closed-log EOF was delivered, that
the classifier's global-IP/30-minute cross-day session model is
equivalent, that both 31-minute late-arrival wings are final, or
that any real independent source/classifier Ed25519 witness signed
the day. The output is always HOLD and publication_authorized=false.

WE2 root-owned future publication still requires genuine owner-signed
ACTIVE genesis on protected GitHub branch, irrevocable transition
verification, root-admitted **distinct** source and classifier public
trust, completed-day EOF and log offsets, signed and immutable daily
certificate ledger, nonroot publisher and timer, and actual website/
Traffic API parity after a real published UTC day. No synthetic day,
invented zero, backfill or unattended run is claimed by this source.
