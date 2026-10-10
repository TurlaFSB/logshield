## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `make check` passes (vet, lint, race tests, coverage floor)
- [ ] New behavior has table-driven tests; a bypass fix adds a regression entry to the corpus
- [ ] Any new payload is inert (reserved names only: example.com, *.invalid, 192.0.2.0/24)
- [ ] The engine stays pure (no I/O, clock, randomness, or global state) and bounded
- [ ] Docs and CHANGELOG updated where behavior changed
- [ ] No secrets, tokens, or real hostnames in code, tests, or fixtures
