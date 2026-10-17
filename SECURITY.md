# Security Policy

LogShield is a security control, so bypasses and vulnerabilities in it matter.
Responsible reports are welcome and appreciated.

## Supported versions

LogShield is pre-release. Only the latest release candidate or release, and the
latest commit on `main`, are supported. After `v1.0.0`, the latest minor release
line receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for a vulnerability.

Use GitHub's private vulnerability reporting:
<https://github.com/TurlaFSB/logshield/security/advisories/new>
(or the **Security** tab, then **Report a vulnerability**). Reports there are
visible only to the maintainer until a fix is published.

Please include:

- a description of the issue and its impact,
- the smallest input or request that reproduces it,
- the version or commit tested.

## What counts

In scope:

- **Detection bypasses**: an encoding, obfuscation, or request-structure trick
  that gets a Log4Shell-class payload past the engine in `block` mode.
- **Engine denial of service**: an input that makes decoding or evaluation use
  unbounded CPU, memory, or time.
- **Proxy flaws**: request smuggling, header handling errors, fail-open
  behavior that was not configured, or log injection through the proxy's own
  logs.
- **Supply-chain issues** in the build, CI, or release process.

Out of scope:

- Vulnerabilities in Log4j itself or in a protected application.
- Attacks that never traverse the proxy (a limitation documented in the threat
  model).
- Reports that require a non-default, explicitly insecure configuration.

## Response targets

- Acknowledgement within 7 days.
- Initial assessment within 14 days.
- Fix or documented mitigation for confirmed issues, with credit to the reporter
  unless anonymity is requested.

This is a student-maintained project, so these are good-faith targets rather
than contractual guarantees.

## Disclosure

We follow coordinated disclosure. We ask for up to 90 days to fix a confirmed
issue before public details, and will say so early if we need less or more.
Confirmed vulnerabilities are published as GitHub Security Advisories (with a
CVE where it applies) and noted in the [changelog](CHANGELOG.md), together with
the fixed version and, for detection bypasses, a regression entry in the
corpus.

## Verifying what you download

Releases are signed and carry provenance and an SBOM. See
[docs/releasing.md](docs/releasing.md) for the exact verification commands, and
treat any binary that does not verify as untrusted.

## Safe-harbor testing

Test only against systems you own or are explicitly authorized to test. Do not
send live exploit payloads or callbacks to third-party infrastructure.
