# Traffic Cockpit API Upgrades — 2026-06-23

Current API head: `886d78e`

## Signals added

- Multi-signal project graph:
  - confirmed humans
  - audience signal
  - page interest
  - first touches
  - unique IPs
  - raw requests
- Browser engagement fields added to live visitor payloads:
  - browser max scroll percent
  - browser clicks
  - browser signal count
  - browser route trail
  - latest meaningful browser event
- Graph spike diagnosis:
  - separates request peak from audience peak
  - reports mixed spike / request wall / audience signal
  - includes request peak and audience peak metrics
- Raw source diagnosis:
  - summarizes top request categories
  - lists top request paths
  - lists top IPs
  - falls back to notification-event source rows when raw entry lookup cannot match the spike bucket

## Notifications

Traffic visitor notifications now use native web push.

Pushover remained configured, but Pushover reported no active devices. Native Traffic web push delivered successfully to the iPhone subscription.

## Important behavior

First touches are intentionally not counted as confirmed humans. They represent browser-shaped, one-page top-of-funnel contact, useful for AoE2 lobby ads and campaign spikes.
