# Governance

LogShield is a small, maintainer-led project. This page says who decides what,
so contributors and adopters know what to expect.

## Roles

- **Maintainer** ([@TurlaFSB](https://github.com/TurlaFSB)): owns the roadmap,
  reviews and merges changes, cuts releases, and handles security reports.
- **Contributor**: anyone who opens an issue or a pull request. Contributors
  follow [CONTRIBUTING.md](CONTRIBUTING.md) and the
  [Code of Conduct](CODE_OF_CONDUCT.md).

New maintainers are added by invitation of the current maintainer, after a
sustained record of good changes and reviews. The rights that matter are
repository admin, release tagging and access to private vulnerability reports.

## How decisions are made

- Changes go through pull requests against `main`. The branch ruleset requires
  passing CI (lint, tests, vulnerability and supply-chain checks); the history
  stays linear.
- Design decisions with lasting consequences are recorded as ADRs in
  [docs/adr](docs/adr). A change that breaks the public surface described in
  [docs/releasing.md](docs/releasing.md) needs an ADR or a changelog entry that
  explains it.
- Detection changes need tests, and bypass fixes need a corpus entry. Evidence
  decides: a rule that cannot show its false-positive rate is not merged.
- Disagreements are settled on the pull request or issue, in public and on the
  technical merits. The maintainer has the final say.

## Releases and security

Releases are cut only by tagging a commit on `main`; the signed, reproducible
pipeline in [docs/releasing.md](docs/releasing.md) does the rest. Vulnerability
reports follow [SECURITY.md](SECURITY.md).

## Continuity

There is currently one maintainer. To keep the project usable if that changes:
everything needed to build, test, release and verify is in this repository and
its CI; there are no secrets to hand over, because releases are signed keylessly
by the workflow itself; and the repository can be forked and rebuilt by anyone.
