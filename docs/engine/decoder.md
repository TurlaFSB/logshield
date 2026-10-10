# Decoder (Step 1b)

`engine.Decode` turns one untrusted string into every plausible decoded variant
("stages"). Rules (added in later steps) inspect all stages, because the
application that eventually logs the value may apply any subset of these
decodings, and the payload only has to be dangerous at the point Log4j sees it.

## Why a search, not a loop

A single "decode until nothing changes" pass cannot tell which intermediate form
a given stack would log. Instead `Decode` does a breadth-first search over chains
of transforms, de-duplicated by text. Every intermediate layer is kept: a value
double-percent-encoded in the request and decoded once by the framework is
logged in its once-decoded form, so that form must be a stage.

The search order is fixed, so output is deterministic.

## Transforms

| Name | Models | Notes |
|---|---|---|
| `gzip` | Compressed bodies | Inflated through a hard output cap. Truncated streams keep what was recovered. |
| `percent` | `%XX` URL decoding | Malformed sequences are left alone. Output may be invalid UTF-8 on purpose. |
| `percent-u` | `%uXXXX` (IIS-style) | Lone surrogates are not decoded. |
| `backslash-escape` | JSON / JavaScript / Java / Python `\uXXXX` (with surrogate pairs) and `\xHH` | `\xHH` at or above 0x80 yields a raw byte so the overlong step can see it. |
| `html-entity` | `&#36;`, `&#x24;`, `&dollar;` | Uses the full HTML5 table from the Go standard library. |
| `overlong-utf8` | Lenient UTF-8 decoders (2-, 3-, 4-byte overlong forms, modified-UTF-8 NUL) | Strictly valid UTF-8 is never touched. |
| `fullwidth` | Applications that apply Unicode compatibility normalization (NFKC) | Fullwidth ASCII and the small-form dollar and braces fold to ASCII. Invalid bytes pass through unchanged. |
| `nul-strip` | UTF-16 / UTF-32 text decoded by the backend, including percent-encoded `%00` forms | Removes NUL bytes. Over-approximates (the backend would not strip NULs from a UTF-8 string), which is the safe direction. |
| `zlib` | `Content-Encoding: deflate` as implemented in practice | Same output cap and truncation handling as `gzip`. |
| `base64` | Cookies, parameters and headers that applications base64-decode before logging | Only whole values of 12 or more base64 characters that decode to valid UTF-8 text without control characters (or to a gzip/zlib stream, which then continues the chain). Binary results are dropped, which discards nearly every random token. |

Log4j itself decodes none of these. They matter because the surrounding stack
often does, and because a WAF that ignores them is trivially bypassed.

## Budgets (fail-closed)

All limits live in `engine.Limits`; a zero field selects its default.

| Limit | Default | Exhaustion |
|---|---|---|
| `MaxInputBytes` | 1 MiB | `input-size`: input is not decoded at all |
| `MaxDepth` | 6 | `depth`: still decodable after 6 chained transforms |
| `MaxStages` | 32 | `stages` |
| `MaxStageBytes` | 2 MiB | `stage-bytes`: also bounds gzip expansion |
| `MaxTotalBytes` | 8 MiB | `total-bytes` |

When any budget is hit, `Result.Exhausted` is set and the caller must block. The
engine never silently truncates and then reports "clean". Hitting a budget on
real traffic is rare (it needs more than six encoding layers, or a decompression
bomb), and that trade-off is intentional.

## Deliberate non-goals

These are not modeled, because Log4j-using stacks do not normally perform them
and modeling them would raise false positives without closing a real bypass.
They are tracked here so the omission is a decision, not an oversight.

- Zero-width and soft-hyphen stripping inside `jndi` (the resolver in 1c handles
  nested lookup syntax; invisible characters do not form a valid lookup name).
- Raw deflate (no header, so it cannot be recognized) and brotli.
- EBCDIC and other legacy code pages are handled only for request bodies with a
  declared EBCDIC charset (see [rules](rules.md)).
- Full Unicode normalization beyond the fullwidth fold above.

If lab validation in Step 3 shows a real stack doing any of these, it becomes a
transform with a regression entry in the bypass corpus.

## Safety properties (tested)

- Stage 0 is always the untouched original.
- No duplicate stages; stage count, per-stage size, and total size respect the limits.
- Same input, same output.
- A 16 MiB gzip bomb is refused, not inflated.
- Fuzzed with `go test -fuzz=FuzzDecode`; the invariants above are asserted on
  every iteration.
