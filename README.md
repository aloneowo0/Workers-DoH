# Workers-DoH v2 — DNS-over-HTTPS Proxy on Cloudflare Workers

A Cloudflare Worker that proxies DNS-over-HTTPS requests across 8 upstream providers with multi-upstream racing, EDNS client-subnet injection, ECH (Encrypted Client Hello) injection for Cloudflare and Meta CDN domains, CDN owner detection via CIDR matching, Twitter/X domain remapping, and IP blocklist filtering.

## Architecture

```
                          ┌──────────────────────┐
                          │     _worker.js        │
                          │  Entry / Router /     │
                          │  Orchestration        │
                          └──────┬───────┬────────┘
                                 │       │
              ┌──────────────────┘       └──────────────────┐
              ▼                                               ▼
   ┌──────────────────────┐                     ┌──────────────────────────┐
   │       mix.js         │                     │    special-domain.js     │
   │  Multi-upstream race │                     │  Domain remap / CDN      │
   │  ECS protect window  │                     │  owner detection / CIDR  │
   └────────┬─────────────┘                     └──────────┬───────────────┘
            │                                               │
            ▼                                               ▼
   ┌──────────────────────┐                     ┌──────────────────────────┐
   │       edns.js        │                     │       resolver.js        │
   │  DNS wire parse /    │                     │  Internal DNS resolver   │
   │  ECS inject /        │                     │  (wire query builder,    │
   │  IP filter           │                     │   multi-upstream race)   │
   └──────────────────────┘                     └──────────────────────────┘
                                                         │
                                                         ▼
                                              ┌──────────────────────┐
                                              │       ech.js         │
                                              │  ECH config fetch /  │
                                              │  HTTPS RR injection  │
                                              └──────────────────────┘
                                                         │
                                              ┌──────────────────────┐
                                              │    homepage.js       │
                                              │  CN/EN homepage      │
                                              │  latency test tool   │
                                              └──────────────────────┘
                                                         │
                                              ┌──────────────────────┐
                                              │     config.js        │
                                              │  Run-time config     │
                                              │  (auto-generated)    │
                                              └──────────────────────┘
```

## Module Reference

| Module | File | Responsibility | Key Exports |
|--------|------|----------------|-------------|
| Entry | `_worker.js` | Request routing, orchestration, special domain pre-processing, single-upstream fallback, DNS wire format construction, SERVFAIL generation | `default.fetch` (handler), `resolveRoute()`, `buildDNS()`, `servfail()` |
| Mix | `mix.js` | Multi-upstream concurrent racing with ECS protect window, post-processing (ECH injection, preferred IP remap) | `concurrentAll()`, `queryUpstream()`, `postProcessBody()`, `answersPass()` |
| EDNS | `edns.js` | DNS packet parsing, EDNS/ECS auto-injection, UDP 4096 / DO bit enforcement, A/AAAA IP blocklist filtering | `prepareQuery()`, `filterAnswers()` |
| ECH | `ech.js` | Fetch CF ECH config via internal DNS, parse HTTPS/SVCB RRs, inject `ech=` and `alpn=` SvcParams into responses | `fetchCFEch()`, `injectECH()`, `META_ECH_B64` |
| Special Domain | `special-domain.js` | Twitter/X domain IP remapping, CDN owner detection (Cloudflare/Meta via CIDR), Meta domain recognition, preferred IP resolution | `remapResponse()`, `resolvePreferredIPs()`, `detectOwner()`, `probeOwner()`, `isMetaDomain()`, `extractIps()` |
| Resolver | `resolver.js` | Internal DNS wire-format query builder, multi-upstream racing for internal lookups (no ECS/EDNS processing), IP byte/string extraction | `resolveDNSWire()`, `extractIPBytes()`, `extractIPStrings()` |
| Homepage | `homepage.js` | Bilingual (CN/EN) management UI with upstream list, EDNS capability table, browser-side latency test tool | `serveHomepage()`, `serveHomepageEn()` |
| Config | `config.js` | Run-time configuration: upstream URLs/ECS flags, timeouts, ECS prefixes, blocked CIDR ranges, region optimizations | `UPSTREAMS`, `ECS_PROTECT_MS`, `HARD_TIMEOUT_MS`, `ECS_PREFIX4`, `ECS_PREFIX6`, `BLOCKED_RANGES`, `MIX_PROVIDER`, `REGION`, `REGION_CONFIG` |

## Endpoints

All endpoints support `POST application/dns-message` (wire format) and `GET ?name=&type=`. Sending `Accept: application/dns-json` triggers RFC 8484 JSON passthrough (proxied to a single upstream).

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Homepage (Chinese) |
| `/en` | GET | Homepage (English) |
| `/health` | GET | JSON health check with upstream list and config state |
| `/dns-query` | GET/POST | Multi-upstream concurrent racing (mix) |
| `/:provider/dns-query` | GET/POST | Single upstream query |

Provider values (depending on `.env` toggles): `google`, `cloudflare_Public`, `quad9`, `adguard`, `opendns`, `dnspod`, `alidns`, `nextdns`, and any `CUSTOM_*` entries.

Supported DNS types: A (default), AAAA, HTTPS(65), SVCB(64), TXT, MX, CNAME, NS, SOA, PTR.

```bash
# GET query (mix mode)
curl "https://your-worker.dev/dns-query?name=example.com&type=AAAA"

# Single upstream
curl "https://your-worker.dev/google/dns-query?name=example.com&type=A"

# POST wire format
curl -X POST -H "Content-Type: application/dns-message" \
  --data-binary @query.bin \
  "https://your-worker.dev/dns-query"

# Base64 dns parameter
curl "https://your-worker.dev/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"

# Health check
curl "https://your-worker.dev/health"
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Domain name to query (paired with `type`) |
| `type` | string | DNS record type, defaults to A |
| `dns` | string | Base64-encoded DNS wire format request (mutually exclusive with `name`) |

## Features

### Multi-upstream Racing (mix.js)

The `concurrentAll()` function in `mix.js` is the core racing engine. It sends the query to all enabled upstreams simultaneously and implements a two-phase strategy:

```
t=0                        Fire all upstreams concurrently
       ┌──────────────── ECS Protect Window (ECS_PROTECT_MS) ────────┤
t~10ms [ECS upstream] arrives, valid → return immediately
t~15ms [Non-ECS upstream] arrives, valid → hold in staging
       ...
t=ECS_PROTECT_MS
       Protect window closes
       Staging has responses → release fastest
       Staging empty → free-for-all race
       ...
t=free race               Any valid response (ECS or not) returns immediately
       ...
t=HARD_TIMEOUT_MS
       Hard timeout
       Staging has responses → release fastest
       All failed → SERVFAIL(code=22, "No reachable upstream")
```

- **ECS_PROTECT_MS** (default 20ms): During this window, only upstreams that support ECS are accepted. Non-ECS responses go to staging. After the window, the fastest staged response is released, and all upstreams race equally.
- **HARD_TIMEOUT_MS** (default 800ms): Total timeout. No further waiting after this.

**Post-processing**: After the fastest valid response is selected, `postProcessBody()` applies ECH injection (for HTTPS RRs on region-activated queries) and preferred IP remap (replaces Cloudflare CDN IPs with a region-optimized domain's resolved addresses).

### EDNS / ECS Injection (edns.js)

All queries pass through `prepareQuery()` which:

1. **ECS injection**: If the request has no EDNS Client-Subnet option, extracts the client IP from `CF-Connecting-IP` and injects a `/24` (IPv4) or `/56` (IPv6) subnet.
2. **UDP 4096**: Forces the OPT record's UDP payload size to 4096.
3. **DO bit**: Sets the DNSSEC OK bit to request DNSSEC records.
4. **IP filtering**: `filterAnswers()` checks all A/AAAA records in the response against `BLOCKED_RANGES`. Records matching any blocked CIDR cause the entire response to be discarded.

ECS depends on the `CF-Connecting-IP` header, which is only available when the Worker runs behind Cloudflare's proxy.

### ECH Injection (ech.js)

For region-activated queries where ECH is enabled (via `REGION_XX_ECH=true` in `.env`):

1. **Cloudflare domains**: `fetchCFEch()` resolves `cloudflare-ech.com` via the internal resolver, parses the HTTPS/SVCB RR from the response, extracts `ech=` and `alpn=` SvcParams, and caches the result for 10 minutes.
2. **Meta CDN domains**: Uses a hardcoded base64-encoded ECH config (`META_ECH_B64`) obtained via TLS retry-config (see `META_ECH_HANDOFF.md`).
3. **Injection**: `injectECH()` parses the upstream's DNS response, finds all HTTPS/SVCB answer records, replaces their `ech=` and `alpn=` parameters with the fetched/hardcoded values, sorts parameters by SvcParam key, and returns a modified DNS response.

If the upstream returned no answers for an HTTPS query, `injectECH()` synthesizes a fresh response with a single HTTPS record containing the ECH config.

### CDN Owner Detection (special-domain.js)

The module compiles two CIDR lists at load time:

- **Cloudflare** (22 IPv4 ranges, 7 IPv6 ranges)
- **Meta** (57 IPv4 ranges, 20 IPv6 ranges)

`detectOwner(ip)` synchronously checks an IP against both compiled sets. `probeOwner(domain)` asynchronously resolves a domain's A records and checks each IP, caching results for 1 hour.

This is used by `postProcessBody()` in `mix.js` to determine whether to inject ECH configs into HTTPS RR responses (only injected for CF and Meta owned CDN domains).

### Domain Remapping (special-domain.js)

When a region is active (e.g., `REGION=CN`), queries for configured remap domains (e.g., `twimg.com`, `twitter.com`, `x.com`, `t.co`) are intercepted:

- **AAAA queries**: Returns an empty answer (disables IPv6).
- **HTTPS queries**: Returns ECH config if available, otherwise an empty answer.
- **A queries**: Resolves the region's preferred domain (e.g., `cf.090227.xyz`) via the internal resolver and returns those IPs with the original query name.

### IP Blocklist (edns.js + config.js)

`BLOCKED_RANGES` defines IPv4/IPv6 CIDR ranges to filter from upstream responses. Any A/AAAA record matching a blocked range causes the entire response to be discarded and replaced with SERVFAIL (with EDE code 17 "Filtered").

Default blocklist: `127.0.0.0/8`, `0.0.0.0/32`, `::/128`, `::1/128`.

## Configuration

Edit `.env` then run `npm run build` to regenerate `config.js`.

```env
# Upstream toggles (true = enabled, false = disabled)
GOOGLE=true
CLOUDFLARE_PUBLIC=true
QUAD9=true
ADGUARD=true
OPENDNS=true
YANDEX=false
DNSPOD=true
ALIDNS=true
360=false
NEXTDNS=true

# Custom upstream (format: CUSTOM_<name>=<DoH URL>)
# CUSTOM_MY=https://my-doh.example.com/dns-query

# Racing parameters (milliseconds)
HARD_TIMEOUT_MS=800
ECS_PROTECT_MS=20

# ECS subnet prefix length
ECS_PREFIX4=24
ECS_PREFIX6=56

# Response IP blocklist (space-separated CIDRs)
BLOCKED_CIDRS=127.0.0.0/8 0.0.0.0/32 ::/128 ::1/128

# Region optimization
REGION=CN
REGION_CN_PREFERRED=cf.090227.xyz
REGION_CN_REMAP=twimg.com twitter.com x.com t.co
REGION_CN_ECH=true
```

The build script in `scripts/build-config.cjs` parses `.env` and generates `config.js` with:

- **UPSTREAMS**: One entry per enabled preset, plus any `CUSTOM_*` entries (default `ecs: true` for custom).
- **BLOCKED_RANGES**: Compiled from `BLOCKED_CIDRS` into `{family, addr, mask}` objects.
- **REGION_CONFIG**: Auto-discovered from `REGION_XX_*` env vars. Each region supports `preferred` (domain for IP remap), `remap` (domains to intercept), and `ech` (boolean to enable ECH injection).

### Preset Upstreams

| Upstream | ECS | URL |
|----------|-----|-----|
| google | yes | dns.google/dns-query |
| cloudflare_Public | no | cloudflare-dns.com/dns-query |
| quad9 | yes | dns11.quad9.net/dns-query |
| adguard | yes | dns.adguard-dns.com/dns-query |
| opendns | yes | dns.opendns.com/dns-query |
| yandex | no | common.dot.dns.yandex.net/dns-query |
| dnspod | yes | sm2.doh.pub |
| alidns | yes | dns.alidns.com |
| 360 | yes | doh.360.cn/dns-query |
| nextdns | yes | dns.nextdns.io |

## Response Headers

| Header | Description |
|--------|-------------|
| `X-Upstream-Time` | Upstream processing time in milliseconds (DNS responses only) |
| `Content-Type` | `application/dns-message` for DNS responses, `application/json` for errors/health |

## Deployment

```bash
cd cloudflare-doh-v2

# 1. Edit .env with your configuration
# 2. Generate config.js from .env
npm run build

# 3. Deploy to Cloudflare Workers
npm run deploy

# Or run locally for development
npm run dev
```

The `predeploy` hook in `package.json` automatically runs `npm run build` before `wrangler deploy`. The `wrangler.jsonc` also configures a build command so CI/CD deploys pick up the same step.

## Testing

```bash
# Unit tests (Vitest configured, currently no test files)
npm test

# Manual endpoint testing
curl "https://your-worker.dev/health"
curl "https://your-worker.dev/dns-query?name=example.com&type=A"
curl "https://your-worker.dev/google/dns-query?name=example.com&type=HTTPS"
```

## Project Structure

```
cloudflare-doh-v2/
├── .env                      # User configuration (edit this)
├── scripts/
│   └── build-config.cjs      # Build script: parses .env, generates config.js
├── config.js                 # Run-time configuration (auto-generated, do not edit)
├── _worker.js                # Worker entry: routing, orchestration, DNS wire construction
├── mix.js                    # Multi-upstream racing with ECS protect window
├── edns.js                   # DNS packet parsing, EDNS injection, IP filtering
├── ech.js                    # ECH config fetch and HTTPS/SVCB RR injection
├── special-domain.js         # CDN owner detection, domain remapping, CIDR matching
├── resolver.js               # Internal DNS resolver (wire queries, multi-upstream race)
├── homepage.js               # Chinese/English management homepage with latency tester
├── META_ECH_HANDOFF.md       # Meta CDN ECH retry-config documentation
├── wrangler.jsonc            # Cloudflare Workers deployment config
├── package.json              # npm scripts and dependencies
└── README.md                 # This file
```

## Notes

- **mix endpoint recommended for production**: Single upstreams may fail due to network instability or policy restrictions. The concurrent racing in `/dns-query` (mix) covers these gaps.
- **CF subrequest limits**: Workers free plan supports ~6 concurrent subrequests, paid plan ~8-10. Enable no more than 8 upstreams to avoid internal queuing.
- **CF-Connecting-IP**: ECS injection depends on this header. Only available behind Cloudflare proxy. For non-CF environments, pass the client IP manually.
- **cloudflare_Public has no ECS**: This upstream does not support EDNS Client-Subnet. Useful for testing the protect window staging mechanism.
- **Custom upstream defaults**: `CUSTOM_*` entries default to `ecs: true`. Adjust in `build-config.cjs` presets if the upstream does not support ECS.
- **Yandex / 360**: Disabled by default. Higher latency or compatibility issues; enable on demand.
- **ECH is region-gated**: ECH injection only activates when `REGION_XX_ECH=true` is set for the requesting client's country. See `META_ECH_HANDOFF.md` for Meta ECH details.
