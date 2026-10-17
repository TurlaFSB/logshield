#!/usr/bin/env python3
"""Stand-in for the JDK's `java`, used only by lab/test/run-smoke.sh.

It serves just enough HTTP for run.sh's readiness checks: the class named on
the command line decides which port it listens on. FAKE_JAVA_FAIL=1 makes it
exit immediately, to exercise the failure path.
"""

import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

if os.environ.get("FAKE_JAVA_FAIL") == "1":
    print("fake java: simulated startup failure", file=sys.stderr)
    sys.exit(1)

cls = sys.argv[-1]
if cls == "Listener":
    port = int(os.environ["CONTROL_PORT"])
elif cls == "Canary":
    port = int(os.environ["CANARY_PORT"])
else:
    print("fake java: unexpected class " + cls, file=sys.stderr)
    sys.exit(2)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
