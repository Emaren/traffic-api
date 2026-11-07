# Traffic private forward-ledger: recovery after a rollup-priority collision

Status: **Source-only / C03 financial HARD HOLD** (2026-11-07).

## Actual physical failure

At 2026-11-07 20:55:57 UTC, traffic-v2-forward-ledger-aoe2hdbets.service
started concurrently with traffic-project-daily-rollups-aoe2hdbets.service.
The forwarder correctly declined with SAFE STOP: RuntimeError STOP: project
rollup worker active, exit status 2, and the unit entered failed. The
hourly Steam security inventory sees the failed protected unit and correctly
declined its next snapshot (MONITOR_ONESHOT_IDENTITY_OR_ACTIVITY_DRIFT).

At 20:59 UTC, after the rollup ended successfully, one native retry of the
**unchanged** confined forwarder completed: Result=success,
ActiveState=inactive, PRIVATE_LEDGER_ONLY, original_history_unchanged=true,
public_audience_writes=false, publish_authorized=false. This **does not**
authorize weakening the forwarder's lock/priority guard.

## Scoped timer repair

Two compatible, minimal controls:

1. After checking exact file paths and the enabled primary rollup timer, only a
   VERIFIED in-flight higher-priority rollup (activating/active/deactivating
   with Result=success) returns an explicit
   DEFERRED_VERIFIED_ROLLUP_IN_PROGRESS / PRIVATE_LEDGER_NOOP response with
   private_ledger_advanced=false and public_audience_writes=false. This leaves
   the checkpoint and ledger untouched and exits0: it is not a successful
   capture and its audit label must never be converted into a capture receipt.
   If rollup Result=exit-code, ActiveState=failed, or state is unrecognized,
   the forwarder still hard-stops; the actual full lock/priority checks remain.
2. Switch the timer from OnUnitInactiveSec=5min to OnUnitActiveSec=5min.
   This re-arms after each start even on a genuine failed attempt, without
   changing the job itself. Preserve boot delay, 15-second accuracy, 30-second
   jitter, and exact service identity. Do not add Restart=always, alter
   protected worker lock semantics, change privileged paths or permit public
   audience writes.

This is a source/test improvement only until a separate, root-reviewed,
automatic-rollback HEL1 timer migration succeeds. Because the original Steam
controller fingerprints the exact loaded timer configuration and result, a
physical edit requires a **fresh, source-bound Steam protected-host admission**
and a real timer after-run PASS. Never change a live unit without coordinating
that admission and restoring the exact preimage on failure.

This is not a C03 global writer-fence acceptance, C06 coordinated capture,
C07 recovery proof or funded WOLO release authorization.
