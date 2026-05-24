# traffic-api

Central analytics, normalization, aggregation, and notification API for Traffic.

## What this API owns

- ingest and normalize nginx/access events
- classify human / bot / suspicious traffic
- build sessions and visitor summaries
- expose overview, project, visitor, and archive endpoints
- persist historical Traffic data
- drive notification policy and provider delivery
- manage operator identities, mutes, and web-push device subscriptions

## Notification model

Traffic notifications follow this pipeline:

1. ingest traffic events
2. normalize host/project/path truth
3. persist Traffic history
4. evaluate notification policy
5. suppress or deliver through the active provider
6. write delivery/suppression history for the admin cockpit

## Notification policy truths

- `selected_projects = []` means wide-open mode across every known project
- `page_hits_only` suppresses API/background routes even if a visitor otherwise looks human
- `filter_exploit_probes` suppresses obvious scanner or exploit-style page paths
- `suppress_operator_traffic` only affects visitors already tagged as operator/self traffic
- operator identities and mute rules are separate systems
- Pushover is supported as a backup transport
- native `web_push` is the preferred direct-open phone-notification transport

## Known production assumptions

- API commonly binds to `127.0.0.1:3345`
- web commonly binds to `127.0.0.1:3045`
- production commonly runs behind nginx and systemd
- durable history currently lives in the Traffic sqlite store unless deployment config says otherwise
- allowed-host coverage must stay aligned with project config or reporting and notification scope will drift

## AoE2 War reporting contract

- `aoe2hdbets` remains the stable Traffic project slug and join key for the HD AoE2 product
- `aoe2war.com` is the canonical public reporting host for that project
- `aoe2hdbets.com` and `api-prodn.aoe2hdbets.com` stay as legacy aliases so historical durable-store rows continue to appear in the same project
- default allowed hosts are derived from `PROJECTS`; if production sets `TRAFFIC_ALLOWED_HOSTS`, keep `aoe2war.com`, `www.aoe2war.com`, `api-prodn.aoe2war.com`, and the legacy aliases in that env value

## Development

```bash
source .venv/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 3345
```

## Verification

```bash
python -m compileall app
python -m unittest discover -s tests
```

Run the narrowest relevant test or smoke path available for the stage you changed:

- ingest
- normalize
- persist
- join
- aggregate
- render
