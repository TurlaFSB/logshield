# Deployment

LogShield is one static binary. Put it between the clients (or your TLS
terminator) and the application it protects, and make the application reachable
**only** through it. A proxy that can be bypassed protects nothing.

## Topologies

| Topology | When | Notes |
|---|---|---|
| Same host, loopback upstream | Unpatchable single host (typical OT/ICS server) | Move the application to `127.0.0.1:<port>`, give LogShield the old public port. Nothing else changes for clients. |
| Separate host or container | Appliance-style, fleets | Firewall the application so only LogShield can reach it. |
| Behind a TLS terminator | Existing nginx, HAProxy or load balancer | Terminate TLS there, forward to LogShield over a trusted network. See [nginx example](../examples/nginx/logshield.conf). |
| LogShield terminates TLS | No terminator available | Set `tls_cert_file` and `tls_key_file` ([configuration](configuration.md)). |

## First rollout

1. Start in **monitor** mode (the default). Nothing is blocked; every verdict is logged and counted.
2. Watch `logshield_requests_total` and the logs for a few days of real traffic. Any `malicious` verdict on traffic you recognise as legitimate is a false positive worth a report.
3. Switch `mode` to `block`. Consider `block_suspicious` once you have seen what your traffic produces for `suspicious` (see [the hardened profile](configuration.md)).
4. Alert on `blocked` events and on any rise in `suspicious`.

## Running it

- **systemd**: [examples/systemd/logshield.service](../examples/systemd/logshield.service). Runs as a dynamic unprivileged user with no capabilities, a read-only filesystem and a syscall filter; `systemd-analyze security` rates it 1.2 (OK). Binding a port below 1024 needs `AmbientCapabilities=CAP_NET_BIND_SERVICE` (and the same in `CapabilityBoundingSet=`), or listen on a high port and redirect.
- **Kubernetes**: [examples/kubernetes/logshield.yaml](../examples/kubernetes/logshield.yaml): non-root, read-only root filesystem, all capabilities dropped, probes on the admin listener, and a NetworkPolicy that makes LogShield the only way in.
- **Container**: the official image arrives with the first release ([roadmap](ROADMAP.md)).

## Operating notes

- **Fail closed.** `on_error: closed` (default) refuses requests when the engine cannot decide; `open` forwards them. Choose open only where availability outweighs the risk, and alert on it.
- **Admin listener.** `admin_listen` exposes `/metrics`, `/healthz` and `/readyz`. It is unauthenticated: bind it to loopback or an internal network only.
- **Sizing.** The proxy adds well under a millisecond at typical load ([load report](load-report.md)); `max_in_flight` bounds concurrency and excess requests get `503`.
- **Logs.** Logs are JSON on stderr and defang `${`, so a downstream Java log pipeline cannot be attacked through them ([observability](observability.md)).
- **Upgrades.** Replace the binary and restart. With a load balancer, set `drain_delay` to its health-check interval so shutdown is graceful.
- **Validate before deploying.** `logshield -check-config -config ...` exits 0 or 2 and prints the effective configuration.

## What this does not replace

Patch Log4j (2.17.1 or later, or remove `JndiLookup`), or retire the host. See the [threat model](threat-model.md) for what the proxy cannot see.
