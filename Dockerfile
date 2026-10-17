# LogShield container image.
#
# The binary is built outside the image by scripts/build-release.sh, so the
# image carries exactly the binary that is in the signed release archive.
# Build context is the dist/ directory:
#
#   scripts/build-release.sh v1.2.3
#   docker buildx build -f Dockerfile --platform linux/amd64,linux/arm64 dist
#
# The base image is distroless "static": no shell, no package manager, no libc,
# runs as an unprivileged user. Dependabot keeps the base current.
FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETARCH
COPY --chmod=0555 image/${TARGETARCH}/logshield /usr/local/bin/logshield

# A container must listen on all interfaces to be reachable; the upstream is
# required and comes from the environment or a mounted configuration file.
ENV LOGSHIELD_LISTEN=0.0.0.0:8080
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/logshield"]
