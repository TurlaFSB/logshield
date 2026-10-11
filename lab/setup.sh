#!/bin/sh
# Run on the lab VM, inside the extracted bundle directory (logshield-lab/).
# Verifies the bundle, unpacks the JDK and compiles the listener and canary.
# Needs: sh, tar, sha256sum. Installs nothing system-wide.
set -eu
cd "$(dirname "$0")"
HERE=$(pwd)

echo "setup: verifying MANIFEST.sha256"
sha256sum -c MANIFEST.sha256 >/tmp/lab-manifest.out 2>&1 || { cat /tmp/lab-manifest.out; echo "setup: bundle is corrupt or modified" >&2; exit 1; }
echo "setup: $(wc -l < MANIFEST.sha256) files verified"

if [ ! -x jdk/bin/javac ]; then
  mkdir -p jdk
  tar -xzf jdk8-linux-x64.tar.gz -C jdk --strip-components=1
fi
JAVAC="$HERE/jdk/bin/javac"
"$HERE/jdk/bin/java" -version 2>&1 | head -1

CP="$HERE/lib/log4j-core-2.14.1.jar:$HERE/lib/log4j-api-2.14.1.jar"
rm -rf classes && mkdir -p classes
"$JAVAC" -source 8 -target 8 -d classes src/listener/Listener.java
"$JAVAC" -source 8 -target 8 -cp "$CP" -d classes $(find src/canary -name '*.java')
echo "setup: compiled OK"
[ -x bin/logshield ] && [ -x bin/labrun ] && echo "setup: binaries present" || echo "setup: WARNING bin/logshield or bin/labrun missing"
