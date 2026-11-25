# Bounded daily audience observation — owner review, not admission

Status: PROPOSED. #31 / #7125555899. Exact predecessor
9d78b50cbbb40ad87caa930e52ecb1e7971d86e2. No production changes.
The legacy metric counts page-bearing operational sessions by session start
date and uses cumulative global IP behavior; an arbitrarily long live session
and future model changes can hold a completed calendar day forever.

## Exact proposed metric v3

For UTC day D define S=D 00:00:00, E=S+24h, W=E+31m. Event times use
normalized UTC and the half-open interval [S,E). W is the minimum delivery
and insertion-completeness watermark, NOT an event lookahead. Every event
has deterministic ordering (timestamp,line_offset,source_rowid). Original
host, visibility, request normalization, filtering and route detection
are retained, pinned and verified. Reject duplicate identities or divergent
raw/ledger identity; prove complete source paging including [S-30m,S)
for carry, with an exact sealed source prefix and insertion clocks.

Group accepted day events by (normalized host, IP, lowercased UA). Split
within the day only when interevent gap strictly exceeds 30 minutes.
Every such day-local slice is attributed to D. Operational sessions remain
unmodified and may continue for days. A cross-midnight continuation is a
new daily observation slice, not a new operational session. Carry-in is
true for the first slice of an actor if its most recent previous-day event
is at most 30 minutes before its first day event; this is audit provenance,
not a counting exclusion. Carry-in uses only the complete preceding
30 minutes. A continuing actor can contribute once per contiguous daily
slice on successive days, even when its operational start predates D.

Run original build_single_session on each slice with now=E (not retry
clock). Use original finalize_bucket, including distributed-burst collapse,
known-visitor and Singapore rules, with minute buckets keyed by slice
first event. Total = page-bearing slices; Potential = original suspected
human predicate; Confirmed = original confirmed subset. These are
daily observed page-session slices, not unique people or completed
operational sessions. Exact same classifier predicates, different unit
of observation and model epoch. Do not claim historical metric parity.
A slice with only API events contributes zero; a later day's page event
cannot add retroactively to D.

Model inputs: original IP behavior predicate using only accepted events
in [S,E), per (host,IP), with request count, direct count, distinct UA/path
sets and existing thresholds. This replaces the cumulative model for v3
and avoids reliance on future data or full historical rebuild. Pin source
commit, normalized row digest, deterministic full daily-model digest,
geo dataset/lookup policy, known-visitor registry, visibility and host
rules, dependencies and classifier configuration; do not allow ambient
mutable geo or identity data. Snapshot dependencies as-of observation
under a reviewed reproducible policy, not at arbitrary signing time.
Prototype calls original classifier and model functions, but deliberately
does NOT implement the production snapshot/adapter or verify supplied
evidence hashes. A real adapter must validate all those byte identities
before invoking classification. No private actor data in public outputs.

## Evidence and late arrivals

Independent upstream must physically establish EOF/delivery completeness
of the interval and closure through W, independent writer insertion
watermark, raw/ledger page chain and matching sealed prefix, no missing
or invalid insertion clocks. No arbitrary timeout interpreted as EOF.
An event with time before E delivered before signing requires reconciliation
against the proposed sealed input; never ignore it because W passed.
If already sealed and a later row has event time before E, record a
durable incident and freeze affected certificate status for operator review
without rewriting values; retain raw bytes; no silent correction or
reclassification of historical certified values. Events at E belong to
the next day. A late event in carry window also invalidates proposed
carry evidence; post-seal discrepancy remains review-only. No missing
evidence treated as observed zero. Genuine zero may be published only by
a separately reviewed v3 zero-day admission contract; current v2 rejects
zero total.

## Production integration requirements — NOT implemented in this draft

A separately reviewed versioned day witness must bind metric version,
day, cutoff, source prefix/pages, evidence, model, dependency and carry
digests, exact counts, late-arrival policy and migration scope. Native
signer allowlist/validation must support the new exact schema with existing
keys; actual Intel upstream and M1 classifier independently sign identical
canonical bytes, then owner signs scoped delegation and ACTIVE state.
Keep distinct signer identities, protected external ruleset #27691195,
revocation checks, source/DB/ingest/API/website pins, root permit, nonroot
publisher and transactionally atomic append. Existing v2 signatures must
not authorize v3; no synthetic signatures, no weakening of trust checks.
Require version-aware certificate ledger and API/chart disclosure; keep
the same three series and real calendar gaps, explicitly mark metric
transition. Do not blend historical and v3 definitions without disclosure.
Preserve 131 historical dates June11–Oct19 byte-identical; unknown dates
remain absent, never insert zeroes to fill gaps. Rebind WE2 renderer to
final live Watcher/Matchups website identity before signing/installation.
Original canonical archive source, all existing publisher modules and
production units remain unchanged in this review PR.

## November 23 proposed migration scope

First eligible v3 review date = 2026-11-23 only, with S=Nov23 00:00Z,
E=Nov24 00:00Z, W=Nov24 00:31Z. Owner must explicitly approve this change
in measurement definition and the one-day migration scope before actual
private calculation/admission. No implicit Oct20–Nov22 backfill. Prior v2
candidate [19786,1355,125] is evidence for a different definition, not
a v3 result; do not transfer it or promise equality. Actual v3 requires
sealed day input and the preceding 30-minute carry source, independent
EOF/writer proof, reproducible classifier dependency snapshot and exact
new model digest. If dependency snapshot cannot be reconstructed, leave
Nov23 UNKNOWN; start with the first prospectively fully instrumented day.
If ordinary delegation age/scope expired, obtain separate explicit
owner admission, never backdate delegation. Subsequent days use same
approved metric and witnesses. No requirement for actual operational
expiry; delivery evidence, trust, resource and release gates can still
legitimately HOLD. Isolated qualification cannot establish live two-day
publication; require two natural distinct-day public API/website proofs.

## Qualification boundary

This source-only prototype is a bounded in-memory review harness with
a 250k event cap (fail closed). No production caller, database write,
native signer, root installation, timer or automation. Test fixture
uses real classification, original burst rules and frozen synthetic
geo/known-visitor dependencies; in-memory SQLite tests only transactional
shape, historical preservation, unknown gaps and retry behavior. Actual
publisher integration, adversarial source adapter, genuine signatures,
versioned admission and native unattended activation are later gates.
For review: approve/reject metric unit, day-only model, E/W boundaries,
carry semantics, late incident policy and Nov23 scope.
