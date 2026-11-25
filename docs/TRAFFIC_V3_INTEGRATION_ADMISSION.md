# V3 integration stage 1: approved source and certificate interfaces

Owner approved V3 architecture and Nov23 scope (PR #84 conversation). This
commit extends the reviewed classifier with a bounded, read-only source
preparation adapter and a distinct signed day schema. The source adapter
requires exact independently pinned as-of dependency and delivery preimages,
source/ledger event parity, receipt clocks, carry and no post-prefix arrivals.
It binds a private day-local model digest and uses only captured geo/identity
lookups during classification. It never queries current geo/identity state as
a substitute. Caller must prove source origin and dependency provenance;
digest and shape validation alone do not establish provenance. Inputs and
per-IP dependencies must remain private. No automatic snapshot acquisition
or source installation is included here.

V3 witness certificate schema is traffic.public-audience.v3.dual-witness-day.v1.
The observation.json companion is mandatory and exact digest-bound. The
existing native signer recognizes the distinct day schema using unchanged
original keys, local terminal constraints and separate roles. The same atomic
publisher stores actual signed schema in the existing ledger and reconciles
exact schema/companion. A separately protected V3 runner.json schema is
required; V2 runner config cannot publish V3, nor may a V3 runner publish V2.
V3 minimum date Nov23; existing delegation, key pins, revision/revocation,
unit, gap renderer, permit, backups, locks, and historical constraints stay
in force. A real V3 zero day still needs separate admission (existing positive
total contract retained). No old candidate value is transferable.

Remaining production integration: genuine acquisition and attestation of
runtime/data dependencies as of cutoff, verified source adapter invocation
and authentic source/writer evidence (including carry), protected root config
and installer review, version-aware public API and website disclosure,
post-seal late incident handling, independent real signing on original
machines, first actual append and next natural timer-backed day. Do not
interpret this code, fixtures or approval comment as a production permit.
If November23 as-of dependency preimage cannot be authenticated, keep it
UNKNOWN. Capture next fully qualified prospective day's dependencies under
reviewed source/host procedure; do not backdate a snapshot.


## Chart / protected configuration binding

The API adds transition metadata only when a real V3 certificate ledger row
and public point agree. It preserves original public points, flags actual
V3 rows, and fails closed on orphan or mixed later schema. WE3 must preserve
the metadata through the website proxy and show the actual first-date
transition before WE2 issues the root-controlled receipt. The V3 runner
requires exactly:
```json
{"approved_source_commit":"<actual deployed website commit>","metric_version_disclosure":true,"renderer_sha256":"<actual activated compiled renderer SHA256>","schema":"aoe2war.traffic-v3.gap-renderer-readback.v1","status":"WE2_ACTIVATED_GAP_RENDERER_READBACK"}
```
The old four-field V2 renderer receipt is NOT sufficient for V3. Existing
certificate schema, original native key identity and external revocation
trust remain protected. V2 append cannot downgrade after V3.
