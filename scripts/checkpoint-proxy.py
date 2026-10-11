#!/usr/bin/env python3
"""Plays a dishonest gateway for smoke.sh and demo.sh.

Serves the note in <checkpoint-file> at GET /v1/log/checkpoint, read on every request, and
forwards every other request to the real gateway. Writes its port to <port-file>.

Usage: checkpoint-proxy.py <port-file> <gateway-url> <checkpoint-file>
"""

import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port_file, upstream, checkpoint_file = sys.argv[1:]
upstream = upstream.rstrip("/")


class Proxy(BaseHTTPRequestHandler):
    def reply(self, status, content_type, body):
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def forward(self):
        if self.command == "GET" and self.path == "/v1/log/checkpoint":
            with open(checkpoint_file, "rb") as f:
                return self.reply(200, "text/plain; charset=utf-8", f.read())
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else None
        req = urllib.request.Request(upstream + self.path, data=body, method=self.command)
        if self.headers.get("content-type"):
            req.add_header("content-type", self.headers["content-type"])
        try:
            with urllib.request.urlopen(req) as resp:
                self.reply(resp.status, resp.headers.get("content-type", ""), resp.read())
        except urllib.error.HTTPError as e:
            self.reply(e.code, e.headers.get("content-type", ""), e.read())

    do_GET = forward
    do_POST = forward

    def log_message(self, *args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
with open(port_file, "w") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
