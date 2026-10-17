#!/bin/sh
# Lab control script. Run on the lab VM from the bundle directory (logshield-lab/).
#
#   ./run.sh start      start listener, canary (hook) and LogShield (block mode)
#   ./run.sh status     show what is running
#   ./run.sh faithful   prove the JNDI hook reports what real Log4j really does on the network
#   ./run.sh run [-- labrun flags]   run the corpora (direct + via LogShield); writes ./lab-out
#   ./run.sh strict [-- labrun flags]   same, with LogShield also blocking suspicious requests -> ./lab-out-strict
#   ./run.sh stop       stop everything
#
# Everything listens on 127.0.0.1 only. Attack payloads in the corpora point at
# reserved names, and the hook canary refuses every lookup, so nothing leaves
# this machine. The "real network" canary is used only by `faithful`, with a
# payload that points at 127.0.0.1.
set -eu
cd "$(dirname "$0")"
HERE=$(pwd)
RUN="$HERE/run"
mkdir -p "$RUN"
JAVA="$HERE/jdk/bin/java"
JOPTS="-Xms16m -Xmx128m -XX:+UseSerialGC"
CP="$HERE/classes:$HERE/lib/log4j-core-2.14.1.jar:$HERE/lib/log4j-api-2.14.1.jar"

CANARY_HOOK_PORT=8080
CANARY_REAL_PORT=8081
PROXY_PORT=8000
ADMIN_PORT=9100
LISTENER_CTRL=9001
LISTENER_TCP=1389
LISTENER_RMI=1099
LISTENER_DNS=off

start_bg() { # name, command...
  name=$1; shift
  nohup "$@" >"$RUN/$name.log" 2>&1 &
  echo $! >"$RUN/$name.pid"
}

alive() { [ -f "$RUN/$1.pid" ] && kill -0 "$(cat "$RUN/$1.pid")" 2>/dev/null; }

waitfor() { # url, seconds
  i=0
  while [ $i -lt "$2" ]; do
    curl -fsS -m 2 -o /dev/null "$1" 2>/dev/null && return 0
    i=$((i + 1)); sleep 1
  done
  return 1
}

start_logshield() { # extra logshield flags
  start_bg logshield "$HERE/bin/logshield" -listen 127.0.0.1:$PROXY_PORT \
    -upstream http://127.0.0.1:$CANARY_HOOK_PORT -mode block -admin-listen 127.0.0.1:$ADMIN_PORT -log-level warn "$@"
}

stop_logshield() {
  if alive logshield; then kill "$(cat "$RUN/logshield.pid")" 2>/dev/null || true; sleep 1; fi
  rm -f "$RUN/logshield.pid"
}

fail_start() { # component
  echo "run: $1 failed to start. Last lines of run/$1.log:" >&2
  tail -n 15 "$RUN/$1.log" >&2 || true
  echo "run: if the process is up but connections to 127.0.0.1 time out, a firewall is dropping loopback traffic (Metasploitable 3 does)." >&2
  echo "run: check with:  sudo iptables -S INPUT   and allow loopback only:  sudo iptables -I INPUT 1 -i lo -j ACCEPT" >&2
  cmd_stop >/dev/null 2>&1 || true
  exit 1
}

cmd_start() {
  [ -x "$JAVA" ] || { echo "run: JDK not set up; run ./setup.sh first" >&2; exit 1; }
  for n in listener canary-hook canary-real logshield; do
    if alive $n; then echo "run: $n is already running; use ./run.sh stop first" >&2; exit 1; fi
  done
  echo "run: starting listener";    start_bg listener env LISTEN_ADDR=127.0.0.1 TCP_PORTS=$LISTENER_TCP,$LISTENER_RMI DNS_PORT=$LISTENER_DNS CONTROL_PORT=$LISTENER_CTRL \
    "$JAVA" $JOPTS -cp "$HERE/classes" Listener
  waitfor http://127.0.0.1:$LISTENER_CTRL/health 30 && alive listener || fail_start listener
  echo "run: starting canary (hook)"; start_bg canary-hook env CANARY_ADDR=127.0.0.1 CANARY_PORT=$CANARY_HOOK_PORT \
    "$JAVA" $JOPTS -Djava.naming.factory.url.pkgs=lab.jndi -cp "$CP" Canary
  waitfor http://127.0.0.1:$CANARY_HOOK_PORT/lab-probe 60 && alive canary-hook || fail_start canary-hook
  echo "run: starting LogShield (block mode)"; start_logshield
  waitfor http://127.0.0.1:$ADMIN_PORT/readyz 20 && alive logshield || fail_start logshield
  echo "run: all three components are up (the real-network canary starts only for 'faithful')"
}

cmd_status() {
  for n in listener canary-hook canary-real logshield; do
    if alive $n; then echo "$n: running (pid $(cat "$RUN/$n.pid"))"; else echo "$n: stopped"; fi
  done
}

cmd_stop() {
  for n in logshield canary-real canary-hook listener; do
    if alive $n; then kill "$(cat "$RUN/$n.pid")" 2>/dev/null || true; fi
    rm -f "$RUN/$n.pid"
  done
  echo "run: stopped"
}

# Prove the oracle: for every probe, the hook must agree with what real Log4j
# does on the network. Positive probes must trigger in both; negative probes
# (schemes the JDK cannot resolve) must trigger in neither.
cmd_faithful() {
  alive listener && alive canary-hook || { echo "faithful: run ./run.sh start first" >&2; exit 1; }
  echo "faithful: starting the real-network canary"
  start_bg canary-real env CANARY_ADDR=127.0.0.1 CANARY_PORT=$CANARY_REAL_PORT "$JAVA" $JOPTS -cp "$CP" Canary
  waitfor http://127.0.0.1:$CANARY_REAL_PORT/lab-probe 60 || { echo "faithful: real canary did not start" >&2; tail -n 15 "$RUN/canary-real.log" >&2; kill "$(cat "$RUN/canary-real.pid")" 2>/dev/null || true; rm -f "$RUN/canary-real.pid"; exit 1; }
  bad=0
  while IFS='|' read -r label pay expect port; do
    [ -n "$label" ] || continue
    curl -fsS -m 5 -X POST http://127.0.0.1:$LISTENER_CTRL/reset >/dev/null
    curl -fsS -m 20 -g -o "$RUN/faithful-real.json" -H "User-Agent: $pay" http://127.0.0.1:$CANARY_REAL_PORT/f
    sleep 1
    curl -fsS -m 20 -g -o "$RUN/faithful-hook.json" -H "User-Agent: $pay" http://127.0.0.1:$CANARY_HOOK_PORT/f
    curl -fsS -m 5 "http://127.0.0.1:$LISTENER_CTRL/events?after=0" >"$RUN/faithful-events.json"
    net=$(grep -o '"kind":"tcp","port":'$port',' "$RUN/faithful-events.json" | wc -l | tr -d ' ')
    if grep -q '"jndi":\["' "$RUN/faithful-hook.json"; then hook=yes; else hook=no; fi
    if [ "$expect" = yes ]; then
      if [ "$net" -ge 1 ] && [ "$hook" = yes ]; then res=PASS; else res=FAIL; fi
    else
      if [ "$net" -eq 0 ] && [ "$hook" = no ]; then res=PASS; else res=FAIL; fi
    fi
    [ "$res" = PASS ] || bad=1
    echo "faithful: $res  $label  expect=$expect  network-connections=$net  hook-saw-lookup=$hook"
    [ "$res" = PASS ] || { echo "--- real canary reply"; cat "$RUN/faithful-real.json"; echo; echo "--- hook canary reply"; cat "$RUN/faithful-hook.json"; echo; }
  done <<'PROBES'
ldap|${jndi:ldap://127.0.0.1:1389/f1}|yes|1389
rmi|${jndi:rmi://127.0.0.1:1099/f2}|yes|1099
ldap-uppercase-scheme|${jndi:LDAP://127.0.0.1:1389/f3}|no|1389
http-scheme|${jndi:http://127.0.0.1:1389/f4}|no|1389
nis-scheme|${jndi:nis://127.0.0.1:1389/f5}|no|1389
PROBES
  kill "$(cat "$RUN/canary-real.pid")" 2>/dev/null || true; rm -f "$RUN/canary-real.pid"
  if [ $bad -eq 0 ]; then echo "faithful: PASS (hook and real Log4j agree on every probe)"; else echo "faithful: FAIL"; exit 1; fi
}

cmd_run() {
  [ "${1:-}" = "--" ] && shift
  exec "$HERE/bin/labrun" -canary 127.0.0.1:$CANARY_HOOK_PORT -proxy 127.0.0.1:$PROXY_PORT \
    -corpus "$HERE/corpus" -out "$HERE/lab-out" "$@"
}

# Re-run the corpora with LogShield also blocking "suspicious" requests
# (-block-suspicious), to measure what the stricter policy would catch and cost.
# Expect FALSE_POSITIVE rows for benign look-alikes: that is the cost being measured.
cmd_strict() {
  alive listener && alive canary-hook || { echo "strict: run ./run.sh start first" >&2; exit 1; }
  stop_logshield
  start_logshield -block-suspicious
  waitfor http://127.0.0.1:$ADMIN_PORT/readyz 20 || { echo "strict: logshield did not become ready" >&2; tail -n 15 "$RUN/logshield.log" >&2; exit 1; }
  [ "${1:-}" = "--" ] && shift
  rc=0
  "$HERE/bin/labrun" -canary 127.0.0.1:$CANARY_HOOK_PORT -proxy 127.0.0.1:$PROXY_PORT \
    -corpus "$HERE/corpus" -out "$HERE/lab-out-strict" -label strict "$@" || rc=$?
  stop_logshield
  start_logshield
  waitfor http://127.0.0.1:$ADMIN_PORT/readyz 20 || echo "strict: warning, normal logshield did not come back" >&2
  return $rc
}

c=${1:-}; [ $# -gt 0 ] && shift
case "$c" in
  start) cmd_start ;;
  status) cmd_status ;;
  stop) cmd_stop ;;
  faithful) cmd_faithful ;;
  run) cmd_run "$@" ;;
  strict) cmd_strict "$@" ;;
  *) sed -n '2,12p' "$0"; exit 2 ;;
esac
