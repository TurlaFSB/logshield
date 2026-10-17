# Using LogShield in OT and ICS environments

Operational technology is where Log4Shell stays alive longest: historians,
SCADA front ends, engineering workstations and vendor appliances embed Java and
Log4j, run on operating systems that cannot be upgraded, and are patched only in
a maintenance window the vendor has certified, if at all. LogShield is built for
that situation: a **compensating control** you can place in front of the
affected web interface without touching the vendor's software.

It is not a substitute for the vendor's fix. Record it as a compensating
countermeasure with an owner, an expiry date and a plan to remove it.

## Where it fits

| Concept | How LogShield maps |
|---|---|
| Zones and conduits (IEC 62443-3-2) | Place the proxy at the conduit into the zone that holds the vulnerable HTTP service, so every request crosses it. It enforces one narrow thing on that conduit: no Log4Shell payloads. |
| Patch management with compensating countermeasures (IEC 62443-2-3) | Document it as the countermeasure for the unpatched asset, with the residual risk from the [threat model](threat-model.md). |
| Defence in depth (NIST SP 800-82 Rev. 3) | One layer. Pair it with segmentation, an egress allow-list on the asset, and monitoring. |
| Asset owner change control | The vendor's software is untouched. Only the network path changes, which is usually a much lighter approval than patching. |

Standards evolve and this table is a pointer, not a compliance claim. Check the
current text of the standards and your own policy.

## Deployment pattern

1. Move the vulnerable service so that it is reachable **only** from the proxy: bind it to loopback and run LogShield on the same host, or firewall it to the proxy's address ([deployment](deployment.md)).
2. Run LogShield in **monitor** mode first. In OT you must know what normal traffic looks like before you can refuse any of it; review the flagged events with the process owner.
3. Switch to **block** mode in a planned window, with a tested rollback (stop the proxy and restore the original port binding).
4. Block outbound LDAP, RMI and DNS from the asset to anything but approved servers. That stops exploitation even for a payload that gets through, and it is a control you can verify independently of LogShield.
5. Forward LogShield's logs and metrics to your monitoring ([observability](observability.md), [Sigma and Prometheus rules](../examples/)).

## The availability decision

In OT, availability usually outranks confidentiality. LogShield offers an
explicit choice rather than hiding it:

- `on_error: closed` (default): if the engine cannot decide, the request is refused. Safe, but a bug could refuse legitimate traffic.
- `on_error: open`: the request is forwarded uninspected. Availability is kept and protection is lost for that request; `logshield_failed_open_total` counts it.

The engine has hard time and size budgets and a 5 ms p99 latency target, so
failures should be extremely rare; the lab measured 0.7 ms added at p99 on one
client. Choose deliberately, write the choice down, and alert on it.

## What is not covered

- Non-HTTP protocols (Modbus, DNP3, OPC UA, MQTT, SNMP, syslog). If a field device name or a syslog message ends up in a vulnerable Log4j, a web proxy never sees it. See [out of scope](threat-model.md#out-of-scope-and-why-it-matters).
- Traffic that bypasses the proxy: another port, another interface, an engineering laptop plugged in directly.
- A compromised asset. This control is on the input path only.

## Evidence for assessors

- Detection against real Log4j 2.14.1: [lab report](lab-report.md), method and limits in [lab.md](lab.md).
- False-positive and bypass measurements: [evaluation report](eval/report.md).
- Supply chain: stdlib-only binary, signed and attested releases ([releasing](releasing.md)).
