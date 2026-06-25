# Traffic Identity Truth Model

Traffic separates browser/network signals from authenticated app truth.

## Rules

- Known IP/fingerprint context is a **Known Signal**.
- Known Signal does not prove a user logged in.
- Known Signal does not prove fresh human presence.
- AoE2WAR authentication/user activity owns login truth.
- Traffic browser telemetry owns browser movement truth.
- Audience-grade human feeds exclude known-only identity signals unless the session independently earns confirmed-human status.

## Important labels

| Label | Meaning |
|---|---|
| Confirmed Human | Browser/page behavior independently looks human enough to count as audience-grade traffic. |
| Likely Human | Browser/page behavior leans human but is not fully confirmed. |
| Known Signal | IP/fingerprint matched a known identity registry entry, but this is context only. |
| Active/Fresh live dot | Recent non-stale browser movement, not login proof. |

## Jim bug fixed

A known player IP could previously make Traffic look like a player had logged in or was active. The fix keeps Jim-like records discoverable in broad history as Known Signal, but removes known-only records from `classification=human_visible`.

Expected checks:

- `classification=human_visible` should return zero Jim known-signal hits.
- Broad history may still show Jim as `Known signal`.
- `human_confirmed` must remain false unless page behavior independently confirms humanity.
