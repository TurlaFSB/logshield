# Configuration

Settings come from four layers; a later layer overrides an earlier one, key by key:

1. Built-in defaults (loopback listener, monitor mode, fail closed).
2. A JSON file: `-config path` or `$LOGSHIELD_CONFIG`.
3. Environment variables `LOGSHIELD_*`.
4. Command-line flags (only the ones you actually pass).

Misspelled keys are refused: an unknown key in the file is an error, and an
unrecognized `LOGSHIELD_*` variable produces a warning at startup. Run
`logshield -check-config ...` to validate everything and print the effective
configuration (the upstream's userinfo is redacted) without starting the proxy.
It exits 0 if valid and 2 if not, which makes it usable as a CI or pre-deploy check.

| JSON key | Environment variable | Flag | Default |
|---|---|---|---|
| `listen` | `LOGSHIELD_LISTEN` | `-listen` | `127.0.0.1:8080` |
| `upstream` | `LOGSHIELD_UPSTREAM` | `-upstream` | required |
| `mode` | `LOGSHIELD_MODE` | `-mode` | `monitor` |
| `block_suspicious` | `LOGSHIELD_BLOCK_SUSPICIOUS` | `-block-suspicious` | `false` |
| `on_error` | `LOGSHIELD_ON_ERROR` | `-on-error` | `closed` |
| `max_body_bytes` | `LOGSHIELD_MAX_BODY_BYTES` | `-max-body` | `1048576` |
| `skip_body_types` | `LOGSHIELD_SKIP_BODY_TYPES` (comma list) | `-skip-body-type` (repeat) | none |
| `forwarded_for` | `LOGSHIELD_FORWARDED_FOR` | `-forwarded-for` | `replace` |
| `rewrite_host` | `LOGSHIELD_REWRITE_HOST` | `-rewrite-host` | `false` |
| `admin_listen` | `LOGSHIELD_ADMIN_LISTEN` | `-admin-listen` | off |
| `max_in_flight` | `LOGSHIELD_MAX_IN_FLIGHT` | `-max-in-flight` | `1024` |
| `log_level` | `LOGSHIELD_LOG_LEVEL` | `-log-level` | `info` |
| `disabled_rules` | `LOGSHIELD_DISABLED_RULES` (comma list) | `-disable-rule` (repeat) | none |

| `tls_cert_file` | `LOGSHIELD_TLS_CERT_FILE` | `-tls-cert` | off (plain HTTP) |
| `tls_key_file` | `LOGSHIELD_TLS_KEY_FILE` | `-tls-key` | |
| `tls_min_version` | `LOGSHIELD_TLS_MIN_VERSION` | `-tls-min-version` | `1.2` |
| `upstream_ca_file` | `LOGSHIELD_UPSTREAM_CA_FILE` | `-upstream-ca` | system roots |
| `upstream_server_name` | `LOGSHIELD_UPSTREAM_SERVER_NAME` | `-upstream-server-name` | the upstream host |

With a certificate and key set, clients are served HTTPS with HTTP/2 and HTTP/1.1
([ADR 0005](adr/0005-tls-termination-and-http2.md)). The files are re-read when
their modification time changes (checked every 10 seconds), so rotation needs no
restart; a broken replacement keeps the working certificate and logs an error.
The https upstream is always verified; use `upstream_ca_file` for a private CA and
`upstream_server_name` when the upstream is addressed by IP.

`disabled_rules` takes rule IDs from the [rule catalogue](engine/rules.md). An
unknown ID is an error (a typo would otherwise leave the rule you meant to
disable active), and the mandatory budget rules (`LSH-3001` to `LSH-3003`) cannot
be disabled.

Credentials in the upstream URL are rejected; the proxy does not forward
authentication and never prints the upstream's userinfo. A complete example is in
[examples/logshield.example.json](../examples/logshield.example.json).

The file is JSON, not YAML or TOML, so the project stays dependency-free; JSON has
no comments, so keep notes in your deployment tooling.

## Containers

```sh
docker run --rm -e LOGSHIELD_UPSTREAM=http://backend:8080 -e LOGSHIELD_LISTEN=0.0.0.0:8080 \
  -e LOGSHIELD_MODE=monitor -p 8080:8080 <image>
```

(An official image arrives with release engineering, Step 3d.)
