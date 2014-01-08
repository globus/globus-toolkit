#! /usr/bin/python

import atexit
import BaseHTTPServer
import re
import os
import json
import signal
import sys

class BarrierServer(BaseHTTPServer.HTTPServer):
    def __init__(self, barrier_size, server_address, bind_and_activate=True):
        self.barrier_size = barrier_size
        self.barrier_data = {}
        BaseHTTPServer.HTTPServer.__init__(self, server_address, BarrierRequest, bind_and_activate)

    def barrier(self, barrier_name, job_id, objects):
        if barrier_name not in self.barrier_data:
            self.barrier_data[barrier_name] = {}

        if len(self.barrier_data[barrier_name]) >= self.barrier_size:
            return (409, "Conflict")
        elif job_id in self.barrier_data[barrier_name]:
            return (409, "Conflict")

        self.barrier_data[barrier_name][job_id] = objects
        return (202, "Accepted")

    def get_barrier_data(self, barrier_name):
        barrier_data = self.barrier_data.get(barrier_name)
        if barrier_data is None:
            return (404, "Not Found", None)
        if len(barrier_data) != self.barrier_size:
            return (503, "Service Unavailable", None)
        barrier_block = []
        for k in barrier_data:
            barrier_block.append(barrier_data[k])
        return (200, "Ok", barrier_block)

class BarrierRequest(BaseHTTPServer.BaseHTTPRequestHandler):
    barrier_re = re.compile("/barrier/([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)")
    barrier_get_re = re.compile("/barrier/([A-Za-z0-9_-]+)")
    decoder = json.JSONDecoder()
    encoder = json.JSONEncoder()

    def do_POST(self):
        m = self.barrier_re.match(self.path)
        if m is not None:
            barrier_name = m.group(1)
            job_id = m.group(2)
            content_length = self.headers.get("Content-Length")
            if content_length is not None:
                objects = self.decoder.decode(self.rfile.read(
                        int(content_length)))

            code, reason = self.server.barrier(barrier_name, job_id, objects)
            self.send_response(code, reason)
            self.end_headers()
        else:
            self.send_response(404, "Not Found")
            self.end_headers()

    def do_GET(self):
        m = self.barrier_get_re.match(self.path)
        if m is not None:
            barrier_name = m.group(1)
            code, reason, data = self.server.get_barrier_data(barrier_name)
            self.send_response(code, reason)
            encoded = None
            if code == 200:
                encoded = self.encoder.encode(data)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", len(encoded))
            elif code == 503:
                self.send_header("Retry-After", "5")

            self.end_headers()
            if encoded:
                self.wfile.write(encoded)
        else:
            self.send_response(404, "Not Found")
            self.end_headers()

def cleanup(*args):
    os.remove("test-coordinator.pid")
    if len(args) > 1:
        os._exit(1)
    os._exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: %s BARRIER-COUNT" % __file__
        sys.exit(1)
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    pid = os.getpid()
    pidfile = file("test-coordinator.pid", "w")
    pidfile.write("%d\n" % pid)
    pidfile.close()
    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, cleanup);

    server_address = ('', 5325)
    httpd = BarrierServer(int(sys.argv[1]), server_address)
    httpd.serve_forever()
