# Threat model

This document states what LogShield defends, against whom, and what it does not
defend. Design decisions are made against it, and it is updated whenever the
evidence changes (the lab results are in [lab-report.md](lab-report.md)).

## What LogShield protects

A host that runs a vulnerable Log4j 2.x and **cannot be patched or reconfigured**
in the near term (end-of-life OS, vendor-locked appliance, OT/ICS endpoint).
LogShield is a *compensating control*: it reduces the chance that attacker input
reaches the vulnerable logging call. It is not a fix and must not be presented as
one. Patching, removing `JndiLookup`, or setting `log4j2.formatMsgNoLookups`
remain the correct mitigations.

## Adversary

- Can send arbitrary HTTP requests to the protected host through the proxy.
- Knows Log4Shell in depth, including public bypass techniques, and can craft
  encodings and obfuscations.
- Can probe LogShield's behavior (responses, timing) and iterate.
- Cannot already execute code on the protected host or on the proxy.

## In scope

| Vector | Handling |
|---|---|
| Request line, path, query | Decoded and resolved |
| Header names and values (User-Agent, X-Forwarded-For, X-Api-Version, Referer, Cookie, custom) | Decoded and resolved |
| Request bodies: JSON, form, XML, multipart, gzip | Decoded and resolved within size limits |
| Obfuscation: nested lookups, defaults, case games, Unicode, layered encodings | Engine |
| Engine denial of service: decompression bombs, deep nesting, huge inputs | Bounded, fail-closed (ADR 0002) |
| Data exfiltration via nested environment lookups in the JNDI key | Reported as a distinct signal |

## Out of scope, and why it matters

| Gap | Consequence |
|---|---|
| Traffic that does not cross the proxy (other ports, other protocols, internal pivots) | No protection; needs network segmentation |
| Non-HTTP inputs that reach Log4j (syslog, MQTT, SNMP, Modbus gateways, device names, DNS names) | Not inspected |
| Second-order injection: data stored earlier and logged later by another component | Not detected at request time |
| TLS that is not terminated at the proxy | Payload is opaque |
| Lookups defined in the application's own Log4j configuration (CVE-2021-45046 patterns) | Not visible to a request scanner |
| Novel encodings the engine does not model | Possible bypass; mitigated by corpus-driven updates |

## Design requirements this implies

1. **Fail closed on budget exhaustion** inside the engine, always.
2. **Inspect what the backend will see.** A proxy and a backend that parse the
   same request differently (header folding, duplicate headers, `Content-Length`
   versus `Transfer-Encoding`, chunk extensions, invalid characters, HTTP/2 to
   HTTP/1 translation) let an attacker hide a payload from the proxy. The proxy
   must forward exactly the bytes it inspected and reject ambiguous requests
   instead of guessing.
3. **Log safely.** The proxy's own logs must defang `${` so they cannot trigger
   a second lookup in a downstream Java log pipeline.
4. **Never fetch.** The engine and proxy never resolve, request, or connect to
   anything named in a payload.
5. **Layered defense.** Pair the proxy with egress filtering on the protected
   host (block outbound LDAP, RMI and DNS except to approved resolvers), which
   stops exploitation even when a payload slips through.

## Parser differentials the engine models

Representation differences between what the engine sees and what the backend
logs are the main source of bypasses, so each one the engine handles has corpus
entries (class `parser-differential`):

- Percent, `%uXXXX`, HTML entity, backslash, overlong UTF-8 and fullwidth forms.
- Gzip and zlib bodies, and base64 values (including base64 of compressed data).
- UTF-16 and UTF-32 (raw, or percent-encoded with `%00`), whatever the declared
  charset, and EBCDIC bodies with a declared EBCDIC charset.
- Basic and Bearer (JWT) credentials, form pairs, and multipart parts.

Known gaps, tracked deliberately:

- Unicode normalization beyond fullwidth ASCII (for example circled or
  superscript letters under NFKC).
- Application-specific encodings (custom ciphers, proprietary serialization).
- A payload assembled from several separate requests or from stored data.
- Duplicate headers that a backend joins with a separator: the join inserts
  a delimiter inside the value, which cannot create a valid lookup that was not
  already visible in one of the parts, so each header is inspected on its own.
  The proxy still must not alter or re-order headers it forwards.

## Residual risk

Any signature-style control can be bypassed by an encoding it does not model. The
project measures this instead of ignoring it: a bypass corpus with provenance, a
benign corpus for false positives, and differential validation against a real
vulnerable Log4j in the lab ([lab.md](lab.md), [lab-report.md](lab-report.md)).

## Proxy-level differentials

The proxy removes framing differentials toward the backend by re-serializing
every request (single `Content-Length`, no `Transfer-Encoding`, no trailers),
sends the request target verbatim, rejects `CONNECT`, `Upgrade`, non-origin-form
targets, `//` prefixes and `#`, and verifies at the last hop that what leaves
equals what was inspected. Requests rejected by Go's own parser are never forwarded and are logged and
counted as `protocol-error`. Verified against Node.js, Python and JDK backends
(`make integration`). Remaining: unsupported protocols (WebSocket) are refused,
and HTTP/2 is terminated rather than relayed, with raw-frame tests for the known differentials (CRLF in values, `transfer-encoding`, `Host` versus `:authority`, trailers, cookie crumbs, interleaved streams); see [ADR 0005](adr/0005-tls-termination-and-http2.md). Details in
[proxy](proxy.md).


## Trust boundaries

```
 clients ──► [ TLS terminator ]? ──► LogShield ──► protected application (vulnerable Log4j)
 (untrusted)                          │  ▲
                                      │  └── configuration file / environment (trusted, operator)
                                      └────► admin listener: /metrics /healthz /readyz (internal only)
```

Everything left of LogShield is untrusted input. The configuration and the
admin network are trusted: whoever can change the configuration can disable the
control, and whoever can reach the admin listener can read operational metrics.

## Attacks on LogShield itself

| Threat | Mitigation | Residual |
|---|---|---|
| Bypass by an encoding the engine does not model | Bypass corpus with provenance, fuzzing, differential validation against real Log4j ([lab-report.md](lab-report.md)) | Possible; see the known gaps above. Layered defences still apply |
| Bypass by a parser differential between proxy and backend | Re-serialisation, verbatim target, forwarded-equals-inspected guard, ambiguous requests rejected, tested against Node.js, Python and JDK backends | Backends we did not test |
| Resource exhaustion (decompression bombs, deep nesting, many fields, slow clients) | Hard budgets that fail closed (`LSH-3001` to `LSH-3003`), body and request limits, read and write timeouts, `max_in_flight` shedding | A volumetric flood is a network-layer problem |
| The proxy's logs become an attack vector | `${` is defanged in every log line | Logs forwarded through other transformations are the operator's concern |
| Spoofed client address | `X-Forwarded-For` is replaced with the connecting address by default; `append` is opt-in | Behind a terminator, configure `append` and trust only that hop |
| Exposed admin listener | Off by default; separate listener; documented as internal only | No authentication on `/metrics`; bind it to loopback or an internal network |
| Tampered configuration | Strict parsing (unknown keys refused), `-check-config`, `disabled_rules` validates IDs, mandatory rules cannot be disabled | A user who can write the file can still set `mode: monitor` |
| Fail-open misconfiguration | Default is fail closed; `on_error: open` is explicit | Operator choice; alert on it |
| Compromised release or dependency | Standard-library-only runtime, `govulncheck`, dependency review, actions pinned by commit, reproducible keyless-signed releases with provenance and SBOM ([releasing.md](releasing.md)) | Toolchain compromise is out of reach for any single project |
| Compromised host running the proxy | None. The proxy runs unprivileged and hardened ([deployment.md](deployment.md)) | An attacker with code execution defeats it |

## What the evidence supports

| Claim | Evidence | What it does not show |
|---|---|---|
| Known public bypass techniques are blocked | 165-entry bypass corpus, 0 misses | Unknown techniques |
| Ordinary traffic is not blocked | 111 hand-written and 100,000 generated benign requests, 0 blocked | Your production traffic |
| The engine agrees with real Log4j | 107 of 107 JNDI attempts by Log4j 2.14.1 were flagged, none forwarded, none missed | Other Log4j versions, JDKs or logging paths; the oracle is "attempted a lookup", not a working exploit |
| The proxy adds little latency | p99 0.7 ms at one client ([load-report.md](load-report.md)) | Production hardware and concurrency |
| Over-blocking is limited | 40 attack-class entries blocked that Log4j ignored (for example unsupported schemes and unterminated lookups), 0 benign blocked | These are deliberate: blocking the whole class is safer than modelling what each Log4j version ignores |
| Non-JNDI lookups pass in the default policy | The lab shows `env`, `sys`, `java`, `date` lookups resolved and forwarded as *suspicious* ([lab.md](lab.md)) | Use `block_suspicious` (the hardened profile) if those lookups matter for your application |

## Operator responsibilities

LogShield only helps when the operator does the following: make the application
unreachable except through the proxy; start in monitor mode and review before
blocking; keep the admin listener internal; alert on blocks and on fail-open
events; and keep working towards the real fix (patch, remove `JndiLookup`, or
retire the host).
