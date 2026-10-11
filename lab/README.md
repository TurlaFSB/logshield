# lab/

Tooling for the differential validation described in [docs/lab.md](../docs/lab.md).

**Only for an isolated lab.** `canary/` is a deliberately vulnerable Log4j
2.14.1 application. Never deploy it, its jars or the bundle anywhere else.

- `canary/` the oracle app and its hermetic JNDI hook
- `listener/` the logging-only listener used to prove the hook is faithful
- `bundle.py` host-side: fetch, verify, build, package
- `setup.sh`, `run.sh` VM-side: set up and operate
