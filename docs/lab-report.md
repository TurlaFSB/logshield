# Lab report: LogShield against real Log4j 2.14.1

The reference result of the differential lab described in [lab.md](lab.md).
Reproduce it with `./run.sh start && ./run.sh faithful && ./run.sh run` and
`./run.sh strict`.

| | |
|---|---|
| Date | 2026-10-17 |
| LogShield / lab code | commit `d572f06` (the lab tooling is unchanged in later commits) |
| Target | Metasploitable 3, Ubuntu 14.04, kernel 3.13.0-24-generic, x86_64 |
| JVM | Temurin OpenJDK 8u504 (bundle verified against the Adoptium SHA-256) |
| Log4j | log4j-core and log4j-api 2.14.1, message lookups on (the vulnerable default) |
| Oracle check | `./run.sh faithful`: 5 of 5 probes agree with real Log4j on the network (2 positive, 3 negative) |
| Corpora | 165 bypass + 111 benign hand-written entries, plus 2,000 generated benign requests (seed 20211209) |

## Balanced profile (default configuration, block mode)


- **Canary**: 127.0.0.1:8080
- **Duration**: 12.528s
- **Engine**: 11 rules
- **Entries**: 2276
- **Label**: ms3-ubuntu1404
- **Proxy**: 127.0.0.1:8000
- **Version**: dev

### Result

**PASS**

| Measure | Count |
|---|---|
| Entries run | 2276 |
| Log4j attempted a JNDI lookup (ground truth) | 107 |
| ...of which the engine flagged malicious | 107 |
| Log4j resolved another lookup only | 16 |
| Log4j only rewrote text (defaults, escapes; harmless) | 81 |
| Log4j left the text unchanged | 2072 |
| No ground truth (indeterminate) | 0 |
| Attack-class entries blocked although Log4j ignored them (over-blocks) | 40 |
| Benign entries run / blocked | 2111 / 0 |
| Proxy phase: blocked / passed / refused | 144 / 1907 / 3 |
| Non-JNDI lookups Log4j resolved that the proxy let through (information, see docs/lab.md) | 14 |
| **MISS** | 0 |
| **LEAK** | 0 |
| **FALSE_POSITIVE** | 0 |
| **EXPECT_MISMATCH** | 0 |
| **INDETERMINATE** | 0 |

### Over-blocks (information)

Attack-class entries the engine blocks although Log4j ignored them.

| ID | Class | Truth | Rules | Proxy |
|---|---|---|---|---|
| cloudflare-http-scheme | public-sample | inert | LSH-1001 | blocked |
| cloudflare-lower-evasion-unterminated | public-sample | inert | LSH-1001,LSH-2002 | blocked |
| fastly-env-leak-unterminated | public-sample | inert | LSH-1001,LSH-1004,LSH-2002 | blocked |
| scheme-nis | protocol-variety | inert | LSH-1001 | blocked |
| scheme-nds | protocol-variety | inert | LSH-1001 | blocked |
| scheme-http | protocol-variety | inert | LSH-1001 | blocked |
| scheme-https | protocol-variety | inert | LSH-1001 | blocked |
| scheme-uppercase | protocol-variety | inert | LSH-1001 | blocked |
| obf-scheme-obfuscated-only | nested-lookup-obfuscation | inert | LSH-1001,LSH-2002 | blocked |
| obf-dotless-i-upper | nested-lookup-obfuscation | inert | LSH-1002,LSH-2002 | blocked |
| enc-percent-twice | encoding | inert | LSH-1002 | blocked |
| enc-percent-thrice | encoding | inert | LSH-1002 | blocked |
| enc-percent-u | encoding | inert | LSH-1002 | blocked |
| enc-html-decimal | encoding | inert | LSH-1002 | blocked |
| enc-html-hex | encoding | inert | LSH-1002 | blocked |
| enc-html-no-semicolon | encoding | inert | LSH-1002 | blocked |
| enc-backslash-u | encoding | inert | LSH-1002 | blocked |
| enc-backslash-u-letters | encoding | inert | LSH-1002 | blocked |
| enc-backslash-x | encoding | inert | LSH-1002 | blocked |
| enc-fullwidth | encoding | inert | LSH-1002 | blocked |
| enc-fullwidth-letters | encoding | inert | LSH-1002 | blocked |
| enc-overlong-percent | encoding | inert | LSH-1002 | blocked |
| enc-html-then-percent | encoding | inert | LSH-1002 | blocked |
| place-header-name | placement | inert | LSH-1001 | refused |
| budget-nesting-40 | resource-exhaustion | lookup-only | LSH-2001,LSH-3002 | blocked |
| budget-lookup-flood | resource-exhaustion | lookup-only | LSH-3002 | blocked |
| budget-percent-depth-12 | resource-exhaustion | inert | LSH-3001 | blocked |
| budget-field-count | resource-exhaustion | inert | LSH-3003 | blocked |
| budget-gzip-bomb | resource-exhaustion | inert | LSH-3001 | blocked |
| diff-percent-encoded-utf16-query | parser-differential | inert | LSH-1002 | blocked |
| diff-nul-interleaved-header | parser-differential | inert | LSH-1002 | refused |
| diff-gzip-then-base64-field | parser-differential | inert | LSH-1002 | blocked |
| diff-base64-query-value | parser-differential | inert | LSH-1002 | blocked |
| diff-base64-url-safe-no-padding | parser-differential | inert | LSH-1002 | blocked |
| diff-base64-cookie-json | parser-differential | inert | LSH-1002 | blocked |
| diff-base64-header | parser-differential | inert | LSH-1002 | blocked |
| diff-double-base64 | parser-differential | inert | LSH-1002 | blocked |
| diff-base64-of-obfuscated | parser-differential | inert | LSH-1002,LSH-2002 | blocked |
| diff-percent-then-base64 | parser-differential | inert | LSH-1002 | blocked |
| diff-multipart-utf16-part | parser-differential | inert | LSH-1002 | blocked |

### Non-JNDI lookups Log4j resolved and the proxy forwarded (information)

| ID | Dataset | Engine | Rules | What Log4j changed |
|---|---|---|---|---|
| fastly-extract-env-path | bypass | suspicious | LSH-2002 | query: `q=$%7Benv:PATH}` to `q=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games`; query.decoded: `q=$%7Benv:PATH}` to `q=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games` |
| fastly-extract-sys-user-name | bypass | suspicious | LSH-2002 | query: `q=$%7Bsys:user.name}` to `q=vagrant`; query.decoded: `q=$%7Bsys:user.name}` to `q=vagrant` |
| fastly-extract-sys-java-version | bypass | suspicious | LSH-2002 | query: `q=$%7Bsys:java.version}` to `q=1.8.0_504`; query.decoded: `q=$%7Bsys:java.version}` to `q=1.8.0_504` |
| fastly-extract-sys-os-version | bypass | suspicious | LSH-2002 | query: `q=$%7Bsys:os.version}` to `q=3.13.0-24-generic`; query.decoded: `q=$%7Bsys:os.version}` to `q=3.13.0-24-generic` |
| fastly-extract-env-user | bypass | suspicious | LSH-2002 | query: `q=$%7Benv:USER}` to `q=vagrant`; query.decoded: `q=$%7Benv:USER}` to `q=vagrant` |
| fastly-extract-java-os | bypass | suspicious | LSH-2002 | query: `q=$%7Bjava:os}` to `q=Linux 3.13.0-24-generic unknown, architecture: amd64-64`; query.decoded: `q=$%7Bjava:os}` to `q=Linux 3.13.0-24-generic unknown, architecture: amd64-64` |
| fastly-extract-date-mm-dd-yyyy | bypass | suspicious | LSH-2002 | query: `q=$%7Bdate:MM-dd-yyyy}` to `q=10-17-2026`; query.decoded: `q=$%7Bdate:MM-dd-yyyy}` to `q=10-17-2026` |
| fastly-extract-date-dd-mm-yyyy | bypass | suspicious | LSH-2002 | query: `q=$%7Bdate:dd:MM:yyyy}` to `q=17:10:2026`; query.decoded: `q=$%7Bdate:dd:MM:yyyy}` to `q=17:10:2026` |
| recursion-deep-nest-8-lower | bypass | suspicious | LSH-2001,LSH-2002 | header:User-Agent: `$%7Blower:$%7Blower:$%7Blower:$%7Blower:$%7Blower:$%7Blower:$%7Blower:$%7Blower:X}}}}}}}}` to `x` |
| lookalike-env-home | benign | suspicious | LSH-2002 | query.decoded: `q=path is $%7Benv:HOME}/x` to `q=path is /home/vagrant/x` |
| lookalike-sys-property | benign | suspicious | LSH-2002 | query.decoded: `q=$%7Bsys:user.dir}` to `q=/home/vagrant/logshield-lab` |
| lookalike-java-version | benign | suspicious | LSH-2002 | query.decoded: `q=$%7Bjava:version}` to `q=Java version 1.8.0_504` |
| lookalike-date-format | benign | suspicious | LSH-2002 | query.decoded: `q=today $%7Bdate:yyyy-MM-dd}` to `q=today 2026-10-17` |
| lookalike-lower-lookup | benign | suspicious | LSH-2002 | query.decoded: `q=$%7Blower:ABC}` to `q=abc` |

## Hardened profile (`-mode block -block-suspicious`)

Same corpora, same canary; only the proxy policy differs.

| Measure | Balanced | Hardened |
|---|---|---|
| Log4j attempted a JNDI lookup / flagged malicious | 107 / 107 | 107 / 107 |
| Misses, leaks, corpus mismatches, indeterminate | 0 | 0 |
| Proxy: blocked / passed / refused | 144 / 1907 / 3 | 170 / 1881 / 3 |
| Non-JNDI lookups forwarded to Log4j | 14 | 0 |
| Benign requests blocked (of 2,111) | 0 | 8 |
| Generated benign requests blocked (of 2,000) | 0 | 0 |

All 8 benign requests the hardened profile blocked are hand-written look-alikes
that literally contain Log4j lookup syntax in a query value (`lookalike-env-home`,
`-sys-property`, `-java-version`, `-date-format`, `-lower-lookup`, `-ctx-lookup`,
`-docker-env`, `-main-args`). Five of them are resolved by a vulnerable Log4j,
which printed the host's home directory, JDK version and date into the log.

## What this does and does not show

- Every JNDI lookup the vulnerable Log4j attempted in this lab was flagged and,
  through the proxy, never reached Log4j: 107 of 107 (0 misses, 0 leaks).
- It does not show the same for other Log4j versions, other JDKs, other logging
  frameworks, or applications that decode input in ways the canary does not
  model; see the limits in [lab.md](lab.md).
- "Attempted a JNDI lookup" is the oracle. Whether an exploit would then work
  depends on the JDK, the gadget classes and the network, which are out of scope.
