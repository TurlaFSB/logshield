# Rules and verdicts

`engine.Inspect(Request, Config) Verdict` is the engine's entry point. It
extracts fields from a request, decodes each into all plausible variants
([decoder](decoder.md)), resolves Log4j lookups in each variant
([resolver](resolver.md)), and turns the findings into rule detections.

## Decisions

| Decision | Meaning | Typical proxy action |
|---|---|---|
| `clean` | No detections. | Forward. |
| `suspicious` | Only suspicious detections. Unusual, not proof. | Monitor, or block in strict mode. |
| `malicious` | At least one malicious detection, or a budget was exhausted. | Block. |

The decision is the highest severity among the detections. Budget exhaustion is
always malicious (fail-closed, ADR 0002).

## Rule catalogue

`engine.Rules()` returns this table programmatically. IDs are stable and never
reused.

| ID | Name | Severity | CVE | Fires when |
|---|---|---|---|---|
| LSH-1001 | jndi-lookup | malicious | 2021-44228 | `${jndi:...}` present as sent |
| LSH-1002 | jndi-lookup-evasive | malicious | 2021-44228 | JNDI lookup revealed only by decoding or nested lookups |
| LSH-1003 | jndi-lookup-possible | suspicious | 2021-44228 | prefix would be `jndi` if an environment lookup supplied the right text |
| LSH-1004 | jndi-key-exfiltration | malicious | 2021-44228 | JNDI key embeds `env`/`sys`/... lookups (data leak over DNS/LDAP) |
| LSH-1005 | jndi-host-allowlist-bypass | malicious | 2021-45046 | authority contains `#` or `@` |
| LSH-2001 | lookup-deep-nesting | suspicious | 2021-45105 | nesting depth reaches `NestingSuspicious` (default 4) |
| LSH-2002 | log4j-lookup-in-input | suspicious | 2021-44228 | non-JNDI Log4j lookup in request data |
| LSH-2003 | lookup-name-built-by-lookups | suspicious | 2021-44228 | lookup name assembled by nested lookups |
| LSH-3001 | decode-budget-exceeded | malicious, mandatory | | decoder hit a limit |
| LSH-3002 | resolve-budget-exceeded | malicious, mandatory | | resolver hit a limit |
| LSH-3003 | request-budget-exceeded | malicious, mandatory | | request hit a whole-request limit |

Mandatory rules cannot be disabled. Any other rule can be listed in
`Config.Disabled` to tune false positives.

## What is inspected

Every value is inspected whole and also by component, because a payload may
only form inside one component and may only make sense across several.

- Method and request-target.
- Query string: each name and each value.
- Every header, name and value, in order, duplicates included.
- `Cookie`: each name and value.
- `Authorization`: the base64-decoded text of `Basic` credentials and of the
  first two segments of a `Bearer` JWT (header and payload). A decoded segment
  containing control bytes is ignored: it is binary, not something an
  application logs. Invalid UTF-8 is kept, because overlong encodings are an
  evasion technique.
- Body: whole, plus each name and value for `application/x-www-form-urlencoded`.

Each detection carries a `Location` (`part` or `part:name`), the decoding `Path`
that revealed it, the JNDI scheme, a defanged evidence excerpt, and key lookups.

## Budgets

`Config` bounds the request (`MaxRequestBytes` 4 MiB, `MaxFields` 1024,
`MaxWorkBytes` 32 MiB of decoded text) on top of the per-field `Limits`. A
request over any bound yields `malicious` with the matching LSH-300x detection.
A proxy that wants to skip large non-text bodies must decide that before calling
`Inspect`, and decide it from the headers it forwards, not from anything the
backend could interpret differently.

## Safe evidence

`engine.Defang` makes attacker text safe for logs and alerts: output is
printable ASCII, `%` and control or non-ASCII bytes become `%XX`, and `{` after
`$` becomes `%7B`, so the output never contains `${`. Evidence is capped at 96
bytes. Never log raw request fields.

## Determinism

The same request and config always give the same verdict, with detections in a
stable order and duplicates (same rule, location, evidence) removed. `Inspect`
does not modify its input.
