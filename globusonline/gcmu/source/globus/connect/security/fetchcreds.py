#! /usr/bin/python
# 
# Copyright 2010-2013 University of Chicago
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

"""
Globus Connect fetchcreds module
"""

import atexit
import copy
import globus.connect.security as security
import os
import pkgutil
import re
import sys
import shutil
import tempfile

from subprocess import Popen, PIPE


class FetchCreds(object):
    """
    This class implements the process of fetching a
    GlobusConnect credential from the GlobusOnline relay server,
    assuming the caller has a valid globusconnect setup
    key
    """

    # Both the 0.9.x and 1.0.x hashes for the Globus Connect CA certificate
    __CA_HASHES = ["4396eb4d", "7a42187f"] 

    def __init__(self, server = "relay.globusonline.org", port = 2223,
            debug = False):
        self.server = server
        self.port = port
        self.cadir = None
        self.certfile = None
        self.keyfile = None
        self.debug = False
        self.pipe_env = copy.deepcopy(os.environ)

        self.data = {}

    def __setup_x509_dirs(self):
        if self.certfile is None:
            old_umask = os.umask(0133)
            self.certfile = tempfile.NamedTemporaryFile()
            anoncert = pkgutil.get_data(
                    'globus.connect.security',
                    'anoncert.pem')
            anonkey = pkgutil.get_data(
                    'globus.connect.security',
                    'anonkey.pem')
            try:
                self.certfile.write(anoncert)
                self.certfile.flush()
            finally:
                pass

            self.pipe_env['X509_USER_CERT'] = self.certfile.name
            if self.debug:
                print "Wrote anoncert to " + self.certfile.name
            os.umask(old_umask)

        if self.keyfile is None:
            old_umask = os.umask(0177)
            self.keyfile = tempfile.NamedTemporaryFile()
            try:
                self.keyfile.write(anonkey)
                self.keyfile.flush()
            finally:
                pass
            os.umask(old_umask)
            if self.debug:
                print "Wrote anonkey to " + self.certfile.name
            self.pipe_env['X509_USER_KEY'] = self.keyfile.name

        if self.cadir is None:
            self.cadir = tempfile.mkdtemp()

            security.install_ca(cadir = self.cadir)
            atexit.register(self.cleanup_cadir)

            if self.debug:
                print "Wrote relay trusted cert to " + self.cadir

            self.pipe_env['X509_CERT_DIR'] = self.cadir
            self.pipe_env['X509_USER_PROXY'] = ''

    def get_cert_and_key(self, code):
        """
        Contact service and get config blob using one time key
        """
        if self.data.get(code) is None:
            match = re.match("^[0-9a-zA-Z-]+$", code)
            if not match:
                raise Exception("Invalid Code '%s'" % code)
            match = re.match("^[0-9a-zA-Z.-]+$", self.server)
            if not match:
                raise Exception("Invalid Server '%s'" % self.server)
            # Race condition: if another process uses ps to see the code, it
            # could conceivably race to relay.globusonline.org to get 
            # the cert/key. Not a dangerous situation, though, because then
            # this would fail, and we'd know something is wrong
            args = ["gsissh", 
                    "-v", "-F", "/dev/null", 
                    "-o", "GSSApiTrustDns no",
                    "-o", "ServerAliveInterval 15",
                    "-o", "ServerAliveCountMax 8",
                    self.server, "-p", str(self.port),
                    "register", code]
            self.__setup_x509_dirs()
            if self.debug:
                print "Executing '" + "' '" + join(args) + "'\n"
            pipe = Popen(args, env = self.pipe_env,
                stdout=PIPE, stderr=PIPE, close_fds = True)
            (out, err) = pipe.communicate()
            returncode = pipe.returncode
            if returncode == 255:
                print "Error: Could not connect to server"
                print "---"
                print err
                return None
            elif returncode > 0:
                print "Error: The server returned an error" 
                print "---"
                print out, err
                return None
            elif returncode < 0:
                print "Error: Could not connect to server" 
                print "---"
                print "Exited abnormaly: received signal " + str(-returncode)
                print out, err
                return None
            self.data[code] = self.parse_config(out)

        return self.data[code]

    def parse_config(self, data):
        """
        Returns a tuple containing the X.509 certificate and private key in pem
        format
        """
        match = re.search("-----BEGIN RSA PRIVATE KEY-----.*" + \
                "-----END RSA PRIVATE KEY-----\n", data, 
                re.MULTILINE | re.DOTALL)
        if not match:
            raise Exception("Private key not found")
        key = match.group()

        match = re.search("-----BEGIN CERTIFICATE-----.*" + \
                "-----END CERTIFICATE-----\n", data, 
                re.MULTILINE | re.DOTALL)
        if not match:
            raise Exception("Certificate not found")
        cert = match.group()
        # config also contains allowed, dns, but we don't use that for GCMU
        return (cert, key)

    def cleanup_cadir(self):
        if self.cadir is not None:
            shutil.rmtree(self.cadir)


if __name__ == '__main__':
    args = sys.argv[1:]
    if not args or args[0] == '-h':
        print "Usage %s code [server]" %(sys.argv[0])
        sys.exit(2)
    code = args[0].strip()
    server = None
    if len(args) > 1:
        server = args[1].strip()
        fetchcreds = FetchCreds(server)
    else:
        fetchcreds = FetchCreds()

    (cert, key) = fetchcreds.get_cert_and_key(code)
    print "cert:\n%s" %(cert)
    print "key:\n%s" %(key)
    sys.exit(0)
#  vim: filetype=python:
