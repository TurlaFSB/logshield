"""Echo backend (Python http.server). Replies with what it received, as JSON.

Python's server does not understand chunked request bodies, which makes it a
useful differential: any framing the proxy leaks would be misread here.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

seq = 0


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_any(self):
        global seq
        seq += 1
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        out = json.dumps({
            "seq": seq, "method": self.command, "target": self.path,
            "version": self.request_version,
            "headers": [x for kv in self.headers.items() for x in kv],
            "body": body.decode("latin1"),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = handle_any

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", int(os.environ["PORT"])), Handler).serve_forever()
