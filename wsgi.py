#
# Copyright 2010-2011 University of Chicago
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import sys
import getopt

# EPEL 6 has a version of jinja2 which works with flask, unlike the
# one in the core rhel/centos/etc repo. This forces that one into
# the path before the normal one
epel_jinja2_egg = "/usr/lib/python2.6/site-packages/Jinja2-2.6-py2.6.egg"
if os.path.exists(epel_jinja2_egg):
    sys.path.insert(0, epel_jinja2_egg)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

sys.path.insert(0, BASE_DIR)

root = "/oauth"
from myproxyoauth import application

### SNIPPET FROM http://tibit.com/code/wsgissl.py
"""
wsgissl.py

Extensions to wsgiref for HTTPS operation.

Written and released to the public domain in 2008 by Forest Wilkinson.
"""

import ssl
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler


class HTTPSMixIn:
    """A MixIn class for adding SSL to BaseHTTPServer.HTTPServer subclasses.
    This works with wsgiref.WSGIServer.
    """
    def set_credentials( self, keypath=None, certpath=None):
        self.keypath = keypath
        self.certpath = certpath

    def finish_request(self, request, client_address):
        """Negotiates SSL and then mimics BaseServer behavior.
        """
        # Note: accessing self.* from here might not be thread-safe,
        # which could be an issue when using ThreadingMixIn.
        # In practice, the GIL probably prevents any trouble with read access.
        ssock = ssl.wrap_socket( request,
            keyfile=self.keypath, certfile=self.certpath, server_side=True)
        self.RequestHandlerClass(ssock, client_address, self)
        ssock.unwrap().close()


class SecureWSGIServer(HTTPSMixIn, WSGIServer):
    pass


class SecureWSGIRequestHandler( WSGIRequestHandler):
    """An SSL-aware WSGIRequestHandler, which sets HTTPS environment variables.
    """
    #xxx todo: set SSL_PROTOCOL, maybe others
    def get_environ( self):
        env = WSGIRequestHandler.get_environ( self)
        if isinstance( self.request, ssl.SSLSocket):
            env['HTTPS'] = 'on'
            env['wsgi.url_scheme'] = 'https'
        env['SCRIPT_NAME'] = root
        return env

### END SNIPPET

if __name__ == "__main__":
    opts, args = getopt.getopt(sys.arg[1:],"c:k:h")
    certfile = None
    keyfile = None
    for (opt, param) in opts:
        if opt == '-c':
            certfile = param
        elif opt == '-k':
            keyfile = param
        elif opt == '-h':
            print "Usage %s [-c CERT-FILE] [-k KEYFILE] | [-h]\n"
            sys.exit(0)
    if certfile is None:
        certfile = os.environ.get("X509_USER_CERT")
    if certfile is None:
        certfile = "/etc/grid-security/hostcert.pem"
    if keyfile is None:
        keyfile = os.environ.get("X509_USER_KEY")
    if keyfile is None:
        keyfile = "/etc/grid-security/hostkey.pem"

    server = SecureWSGIServer(("localhost", 8443), SecureWSGIRequestHandler)
    server.set_app(application)
    server.set_credentials(keypath=keyfile,certpath=certfile)
    server.serve_forever()
# vim:filetype=python:nospell:
