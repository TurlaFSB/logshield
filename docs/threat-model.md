# Threat model (draft)

This is an early version, written before the proxy exists so that design
decisions are made against it. Step 3e finalizes it with lab results.

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
| Obfuscation: nested lookups, defaults, case games, Unicode, layered encodings | Engine (Steps 1b and 1c) |
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
   HTTP/1 translation) let an attacker hide a payload from the proxy. Step 2
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
vulnerable Log4j in the lab (Step 3c).

## Proxy-level differentials (Step 2a)

The proxy removes framing differentials toward the backend by re-serializing
every request (single `Content-Length`, no `Transfer-Encoding`, no trailers),
sends the request target verbatim, rejects `CONNECT`, `Upgrade`, non-origin-form
targets, `//` prefixes and `#`, and verifies at the last hop that what leaves
equals what was inspected. Requests rejected by Go's own parser are never forwarded and are logged and
counted as `protocol-error`. Verified against Node.js, Python and JDK backends
(`make integration`). Remaining: unsupported protocols (WebSocket) are refused,
and HTTP/2 will need its own differential review when TLS is added. Details in
[proxy](proxy.md).
