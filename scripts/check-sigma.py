#!/usr/bin/env python3
"""Structural check of examples/sigma/*.yml and the Prometheus rules (PyYAML only).

It verifies what a SIEM converter needs: required Sigma fields, a UUID id, a known
level, a log source, and a detection block whose condition names existing
selections. It is not a full Sigma parser; convert the rules with sigma-cli
for your SIEM before relying on them.
"""

import glob
import re
import sys
import uuid

import yaml

LEVELS = {"informational", "low", "medium", "high", "critical"}
REQUIRED = ("title", "id", "status", "description", "logsource", "detection", "level")


def check_sigma(path):
    errors = []
    with open(path, encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    for key in REQUIRED:
        if key not in rule:
            errors.append(f"missing {key}")
    try:
        uuid.UUID(str(rule.get("id")))
    except ValueError:
        errors.append("id is not a UUID")
    if rule.get("level") not in LEVELS:
        errors.append("unknown level")
    if not rule.get("logsource", {}).get("product"):
        errors.append("logsource.product missing")
    det = rule.get("detection") or {}
    cond = det.get("condition")
    names = [k for k in det if k != "condition"]
    if not isinstance(cond, str) or not names:
        errors.append("detection needs a condition and at least one selection")
    else:
        for word in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", cond):
            if (
                word not in {"and", "or", "not", "of", "them", "all", "1"}
                and word not in names
            ):
                errors.append(f"condition refers to unknown selection {word!r}")
    for name in names:
        if not det[name]:
            errors.append(f"selection {name!r} is empty")
    return errors


def main():
    bad = 0
    files = sorted(glob.glob("examples/sigma/*.yml"))
    if not files:
        print("no Sigma rules found", file=sys.stderr)
        return 1
    for path in files:
        for err in check_sigma(path):
            print(f"{path}: {err}", file=sys.stderr)
            bad += 1
    with open("examples/prometheus/logshield.rules.yml", encoding="utf-8") as f:
        rules = yaml.safe_load(f)
    for group in rules["groups"]:
        for r in group["rules"]:
            if not r.get("alert") or not r.get("expr"):
                print(f"prometheus: rule without alert or expr: {r}", file=sys.stderr)
                bad += 1
    print(
        f"checked {len(files)} Sigma rules and the Prometheus rules: {'FAIL' if bad else 'ok'}"
    )
    return 1 if bad else 0


sys.exit(main())
