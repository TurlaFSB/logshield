# Releasing and verifying LogShield

## Versioning

LogShield follows [Semantic Versioning](https://semver.org/). The public surface
that the version number protects is:

- the command-line flags, `LOGSHIELD_*` variables and JSON configuration keys, and their defaults;
- the metric names and labels, and the structured log event names and fields;
- rule IDs (`LSH-xxxx`) and their meaning (severity, mandatory or not);
- the verdict semantics: what `malicious` and `suspicious` mean, and the HTTP behaviour of block, monitor and fail-closed.

A change that breaks any of these is a **major** release. New rules, new
decodings, new settings and new metrics are **minor**. Detection can only get
stricter within a major version, apart from false-positive fixes, which are
called out in the changelog. Fixes are **patch**. Security fixes go to the
latest minor of the latest major.

## What a release contains

Each tagged release is built by `.github/workflows/release.yml` from that tag
and nothing else:

| Artifact | Purpose |
|---|---|
| `logshield_<version>_<os>_<arch>.tar.gz` / `.zip` | Static binaries (Linux, macOS, Windows), with license, README, changelog and examples |
| `SHA256SUMS`, `SHA256SUMS.sigstore.json` | Checksums, signed keylessly with Sigstore |
| `logshield.spdx.json` | SBOM (SPDX) of the source tree |
| Build provenance attestation | SLSA-style provenance for every archive, from GitHub's attestation service |
| `ghcr.io/turlafsb/logshield:<version>` | Distroless, non-root, multi-arch image, signed, with provenance and SBOM attached |

The archives are reproducible: the same commit and the same Go toolchain give
byte-identical files (`make release-dry-run` twice and compare `dist/SHA256SUMS`;
CI does this on every change).

## Verifying a download

You need [cosign](https://docs.sigstore.dev/cosign/) and, for attestations, the
GitHub CLI. Replace `v1.2.3` with the release you downloaded.

```sh
# 1. Checksums are signed by this repository's release workflow.
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/TurlaFSB/logshield/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

# 2. Your archive matches the signed checksums.
sha256sum --check --ignore-missing SHA256SUMS

# 3. Build provenance: this archive was built from this repository by that workflow.
gh attestation verify logshield_v1.2.3_linux_amd64.tar.gz --repo TurlaFSB/logshield

# 4. The container image.
cosign verify ghcr.io/turlafsb/logshield:v1.2.3 \
  --certificate-identity "https://github.com/TurlaFSB/logshield/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/turlafsb/logshield:v1.2.3 --repo TurlaFSB/logshield
```

In production, pin the image by digest (`ghcr.io/turlafsb/logshield@sha256:...`)
rather than by tag.

## Cutting a release (maintainers)

1. `main` is green. Run `scripts/repo-settings.sh --protect` once, before the first release, so `main` requires pull requests and passing checks.
2. Move the `[Unreleased]` entries in `CHANGELOG.md` under a new `## [x.y.z] - date` heading.
3. Tag the merge commit and push the tag: `git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`. Use a suffix such as `-rc.1` for a pre-release (no `latest` image tag, marked as a pre-release).
4. The workflow tests, builds, signs, attests, pushes the image and creates the GitHub release. If anything fails nothing is published half-way: re-run the workflow, or delete the tag and the draft artifacts and start again.
5. Verify the release with the commands above before announcing it.
