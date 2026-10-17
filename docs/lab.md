# Lab: differential validation against real Log4j

The engine's corpora say what *we think* is an attack. The lab asks the harder
question: **does a real, vulnerable Log4j actually act on this request, and did
LogShield stop it?** Every miss found here is a miss that matters.

## What is compared

For each corpus entry the runner (`cmd/labrun`) gets three answers:

| Answer | From |
|---|---|
| **Truth**: did Log4j attempt a JNDI lookup? | The *canary*, a small HTTP app that logs every part of every request through **Log4j 2.14.1** with lookups on, then reports what Log4j rendered and which JNDI names it tried to resolve. |
| **Engine**: what does LogShield decide? | `engine.Inspect`, run locally with default settings. |
| **Proxy**: does the request get through? | The same request sent through a real LogShield process in **block** mode in front of the canary. |

```text
labrun --direct-->  canary (Log4j 2.14.1)  --> truth
labrun --engine-->  verdict
labrun --via----->  LogShield (block) --> canary  --> blocked | passed (+ what Log4j did)
```

## Pass and fail

| Problem | Meaning | Fails the run |
|---|---|---|
| `MISS` | Log4j attempted a JNDI lookup, the engine did not say *malicious* | yes |
| `LEAK` | Log4j attempted a JNDI lookup on a request that came through the proxy | yes |
| `FALSE_POSITIVE` | a benign entry was blocked | yes |
| `EXPECT_MISMATCH` | the engine disagrees with the corpus entry | yes |
| `INDETERMINATE` | an attack entry got no ground truth (the canary rejected it or timed out), so it proves nothing | yes |
| over-block | an attack-class entry that Log4j ignored but the engine blocks | no, counted |
| rewrite-only | Log4j only rewrote text, such as a default `${x:-d}` or a `$${` escape | no, counted |
| non-JNDI lookups passed | Log4j resolved a lookup such as `${env:...}` or `${java:...}` and the proxy forwarded it | no, counted (information) |

The last row is a policy point, not a defect. Those requests are *suspicious*,
not malicious, and the default configuration forwards suspicious requests.
Set `-block-suspicious` to block them (see [configuration](configuration.md)).
A proxy outcome of **refused** means an error status that is not the block
status and carries no canary reply: LogShield refused a malformed request, or
the canary answered with an error. No Log4j effect was observed.

Over-blocks are expected: the engine is deliberately conservative (it blocks
malformed or over-budget input, which fails closed). The report counts them so
the cost is visible.

## The oracle, and why it is hermetic

The corpora point at reserved names (`192.0.2.1`, `example.com`), so a real
network listener would never see them. Instead the canary runs with
`-Djava.naming.factory.url.pkgs=lab.jndi`. JNDI then resolves `ldap://`,
`ldaps://`, `rmi://`, `dns://`, `iiop://`, `iiopname://`, `corba://` and `corbaname://`
(every URL scheme the JDK 8 ships a factory for) through recording stubs (`lab/canary/lab/jndi`) that note the exact name and refuse the lookup.
It is Log4j itself that parses the (possibly obfuscated) text and calls
`InitialContext.lookup`; we only watch the call. No packet is ever sent.

Because a stub is not the JDK, the lab proves the stub is faithful with
`./run.sh faithful`. A second canary without the hook sends real lookups to a
logging-only listener on `127.0.0.1`, and the hook canary must agree on every
probe: `ldap://` and `rmi://` must trigger in both; an uppercase `LDAP://`
scheme, `http://` and `nis://` (which the JDK cannot resolve) must trigger in
neither.

### What the canary logs

For every request it logs the method, path, query, header names, header values
and body exactly as sent, plus their URL-decoded forms, **and the views a
mainstream application stack would hand to a logger** (`lab/canary/AppViews.java`,
tested by `make lab-java`): form fields, cookies (percent-decoded), the Basic
credential (whole, and split at the first colon like servers do), JWT segments,
JSON string escapes, bodies decoded with the declared charset or sniffed
UTF-16/32, gunzipped or inflated bodies, and multipart parts with their
charsets. Log4j itself decodes none of these, but applications routinely do,
and the Basic-auth user name is the classic Log4Shell vector.

Not modelled, because frameworks do not do them by default: HTML entities,
backslash escapes, full-width forms, overlong UTF-8, repeated percent-decoding
and base64 inside base64. The engine still blocks these (it assumes any
downstream decoding), and the report counts them as over-blocks.

## Containment

- Everything binds `127.0.0.1`. The lab VM is on a host-only network.
- The hook canary refuses every lookup, so a payload cannot cause a callback,
  class loading or code execution. The listener never answers with anything a
  JNDI client could interpret (TCP is read once and closed; DNS answers only
  `127.0.0.1`).
- The only network-capable canary (`canary-real`) is used by `faithful` with a
  payload that points at `127.0.0.1`.
- Reports contain payloads only defanged (`${` is written `$%7B`).
- The vulnerable Log4j runs as a throwaway process on a VM that is meant to be
  vulnerable. Do not copy the canary, the jars or the bundle anywhere else.

## Layout

| Path | Purpose |
|---|---|
| `lab/canary/` | `Canary.java` (the oracle app) and `lab/jndi/` (the recording hook) |
| `lab/listener/` | `Listener.java`, the logging-only TCP/DNS listener and its control API |
| `lab/bundle.py` | Run on the **host**: downloads and verifies the JDK and jars, builds Linux binaries, writes a manifest and a tarball |
| `lab/setup.sh`, `lab/run.sh` | Run on the **VM**: verify, compile, start, `faithful`, `run`, stop |
| `internal/lab`, `cmd/labrun` | Request builder, classification, report (unit-tested with fakes and the real proxy) |

## Reading the result

Reference run (Metasploitable 3, Ubuntu 14.04, OpenJDK 8u504, Log4j 2.14.1,
2,276 entries: the hand-written corpora plus 2,000 generated benign requests):

| Outcome | Count |
|---|---|
| Real JNDI lookups by Log4j | 107, all flagged malicious by the engine |
| Misses, leaks, false positives, corpus mismatches, indeterminate | 0 |
| Over-blocks (attack-class, Log4j ignored) | 40 |

The 40 over-blocks are not noise; each group has a reason:

| Group | Why Log4j ignored it | Why the engine still blocks it |
|---|---|---|
| Scheme variants (`nis`, `nds`, `http`, `https`, uppercase `LDAP`) | The JDK has no provider for them. `faithful` proves it against real Log4j. | Other JNDI providers exist on application servers; the cost of blocking is near zero. |
| Unterminated `${jndi:...` | Log4j does not resolve an unclosed lookup. | A truncating proxy or a later concatenation can complete it. |
| Exotic encodings (HTML entities, `\x`, full-width, overlong, repeated percent-encoding, base64 in arbitrary fields, UTF-16 without a label) | Neither Log4j nor mainstream frameworks decode them by default. | The engine assumes any downstream decoder (defence in depth, ADR 0002). |
| Resource budgets (nesting, field count, decompression bomb) | Not a lookup. | Fail closed by design. |
| Malformed framing refused by Go (NUL-interleaved header, bad header name) | Never reaches the application. | The refusal is the protection. |

Everything a mainstream stack decodes (Basic-auth, JWT, forms, cookies, JSON
escapes, declared or sniffed charsets, gzip, labelled multipart parts) is
modelled by the canary, and those cases are counted among the 107 real triggers.

### The policy question: suspicious requests

Fifteen requests made Log4j resolve a non-JNDI lookup (`${env:...}`,
`${sys:...}`, `${java:...}`, `${date:...}`) and were forwarded, because the
engine rates them *suspicious* and the default configuration does not block
suspicious requests. They disclose host details into logs but do not open a
network connection. `./run.sh strict` re-runs everything with
`-block-suspicious` to measure the effect: what it would catch, and which
benign look-alikes (documentation, templates) it would also block.

## Prerequisites on the VM

- **Loopback must be reachable.** Metasploitable 3's iptables INPUT chain ends in
  `DROP` with no rule for the loopback interface, so connections from
  `127.0.0.1` to the lab's own listeners time out. Allow loopback only, and
  remove the rule afterwards:

  ```sh
  sudo iptables -I INPUT 1 -i lo -j ACCEPT
  # when finished
  sudo iptables -D INPUT -i lo -j ACCEPT
  ```

  This opens nothing to the network. It is not persisted across reboots unless
  the VM saves its rules.
- About 400 MB of free RAM (two JVMs capped at 128 MB, plus LogShield).

## Running it

On the host (any OS with Python 3, and Go if you want fresh binaries):

```sh
python3 lab/bundle.py --out lab-bundle
# copy lab-bundle/logshield-lab.tar.gz to the VM and compare its sha256
```

On the VM:

```sh
tar xzf logshield-lab.tar.gz && cd logshield-lab
./setup.sh          # verify manifest, unpack JDK 8, compile
./run.sh start
./run.sh faithful   # must print PASS before the results mean anything
./run.sh run        # corpora, direct + via LogShield -> lab-out/report.md
./run.sh stop
```

`bundle.py` verifies the JDK against the Adoptium API's SHA-256 and each jar
against Maven Central's `.sha1`, and writes the SHA-256 of everything it fetched
to `VERSIONS.txt`, so the artifacts can be cross-checked independently.

## Limits of this lab (read before quoting a result)

- **One Log4j version.** Only 2.14.1 with message lookups on. Versions 2.15 to
  2.16 behave differently by design, and LogShield is for hosts that cannot be
  patched, so 2.14.1 is the representative case. It is not a proof about other
  versions or about Logback and other loggers.
- **One logging path.** The canary logs each value as the message (`%m`).
  Applications that log through other layout fields or `ThreadContext` can
  reach lookups differently. The engine does not depend on the logging path,
  but this lab does not test those paths.
- **The oracle is the JNDI call, not exploitation.** "Triggered" means Log4j
  asked to look the name up. Whether an exploit then succeeds depends on the
  JDK, the gadget classes and the network, which are out of scope.
- **The canary's HTTP reader is lenient on purpose.** It takes the request
  target and header names and values exactly as sent (`lab/canary/RawHttp.java`,
  tested by `make lab-java`), so payloads in the path, query or header names
  reach Log4j. A strict server in front of a real application might refuse some
  of these requests before the application logs them; that makes the canary the
  worst case, not an optimistic one. Entries the canary still cannot answer are
  reported as `INDETERMINATE`, never as passes.
- **Only corpus requests are sent.** Novel evasions are found by the fuzzers
  and by adding what the lab finds back into the corpus.
