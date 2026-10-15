# Human-first live Traffic — October 15, 2026

## Evidence that motivated this patch

Production Nginx log census (2026-10-15, UTC; one general access log, not a double-counted sum):

- 00:00 hour: 33,184 requests across AoE2WAR and its chain hosts; 17,212 successful, unique /rpc-mainnet/block_results heights (a structured scan).
- 10:00 hour: 15,838 requests; 1,301 Operator Bridge calls, 989 watch-stream calls and 832 Radio WOLO station calls.
- Ashburn GEOIP results from the main web host: 254 / 207 / 223 requests at 00:00 / 10:00 / 16:00 UTC; most were one-hit Linux Chrome clients, with identifiable SemrushBot alongside.
- The main access log and the dedicated AoE2WAR access log overlap. Traffic runtime uses TRAFFIC_LOG_PATH=/var/log/nginx/access.log; no duplicate Traffic source was demonstrated.
- Nginx JSON presently includes remote_addr and x_forwarded_for but **does not** include CF-Connecting-IP, so code support for the latter is forward-compatible and cannot repair past data.

## Live preview contract

- Raw Traffic event persistence and historical sessions remain unchanged.
- The *nonhuman preview only* groups classified bot, browser_script, script_burst, and suspicious sessions by project, hostname, GeoIP geography, classification, automation family, exact user agent and **UTC hour**.
- No authenticated, confirmed-human, or independently known-human session is aggregated.
- Existing backend security/page burst clusters pass through unchanged.
- Aggregation precedes the eight-row-per-review-lane response limit so IP fanout is summarized rather than sliced into unrelated singletons.
- Cluster counters describe **sessions and unique IPs**, not unique real humans. Sample IPs/paths are bounded to 12 each; raw evidence stays in history.
- Singletons and low-confidence unknown/candidate visitors retain their individual records.
- Browser app activity and Watcher funnel signals are not forced into nonhuman clusters.

## Cloudflare provenance

Traffic will prefer cf_connecting_ip only when remote_addr is a recognized Cloudflare network address and the recorded IP value is valid. Legacy X-Forwarded-For is used only from a trusted peer if the new field is absent. Untrusted direct callers cannot force either header.

**Deployment dependency:** the Nginx traffic_master JSON log format must be separately reviewed and upgraded to include:
    "cf_connecting_ip":"$http_cf_connecting_ip"

Do **not** change real_ip_header or set_real_ip_from at the same time without auditing the impact on the raw socket-peer identity. Otherwise remote_addr may cease to represent the original Cloudflare edge, defeating the trust check. Ensure the value is logged with escape=json and nginx -t succeeds. First collect read-only request samples, then deploy via the established source/receipt-controlled Nginx workflow. Do not infer Cloudflare provenance from old logs that lack the field.

## Validation

1. Run: python -m unittest discover -s tests -v
2. Verify 200 synthetic one-hit browser-script sessions collapse to one preview card, with a count of 200 and a bounded sample.
3. Verify confirmed/likely humans, authenticated visitors and confirmed known humans remain separate.
4. Verify an untrusted direct socket cannot spoof CF-Connecting-IP or X-Forwarded-For.
5. Verify real API response preview lengths stay <= 8 and existing project/visitor metrics remain unchanged.
6. Review production Nginx host/IP/UA evidence; do not claim a reduced origin CPU load until measured separately.

Do not change WoloChain, settlement, Nginx, CI production gates, database rows or DNS as part of deploying these source changes.
