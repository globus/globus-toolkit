#!/usr/bin/python -u
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

"""
Globus Connect Setup for linux / mac
Compatible with OS X 10.4 (python 2.3.5)
Initialize ~/.globusonline/lta directory if it doesn't exist.
Contact transfer service over gsissh and retrieve security config.

Requires: GLOBUS_LOCATION
Dependencies: gsissh
"""
import re
import sys
import os
import time
import signal

try:
    GLOBUS_LOCATION = os.environ['GLOBUS_LOCATION']
except KeyError:
    raise Exception("Need GLOBUS_LOCATION defined")

try:
    GC_ROOT = os.environ['GC_ROOT']
except KeyError:
    raise Exception("Need GC_ROOT defined")

EXE_DIR = os.path.dirname(sys.argv[0])
TOP_DIR = os.path.expanduser(GC_ROOT)
CONFIG_DIR = os.path.join(TOP_DIR, "etc", "grid-security")

# User configs
SERVICE_CERT = os.path.join(CONFIG_DIR, "ltacert.pem")
SERVICE_KEY = os.path.join(CONFIG_DIR, "ltakey.pem")
GRIDMAP_FILE = os.path.join(CONFIG_DIR, "grid-mapfile-go")

X509_CERT_DIR = os.path.join(CONFIG_DIR, "certificates")

os.environ['X509_USER_PROXY'] = ""
os.environ['X509_CERT_DIR'] = X509_CERT_DIR

# Linux
os.environ['LD_LIBRARY_PATH'] = "%s/lib:%s" % (
	GLOBUS_LOCATION, os.getenv('LD_LIBRARY_PATH', ""))
# Mac
os.environ['DYLD_LIBRARY_PATH'] = "%s/lib:%s" % (
	GLOBUS_LOCATION, os.getenv('DYLD_LIBRARY_PATH', ""))
GSISSH = os.path.join(GLOBUS_LOCATION, "bin", "gsissh")

class Config: pass


def make_dir(dir):
    if not os.path.exists(dir):
        os.mkdir(dir)


def run_cmd(cmd, args):
    """
    We don't have access to subprocess.  Do it the manly way.
    """
    stdout_pipe = os.pipe()
    stderr_pipe = os.pipe()
    pid = os.fork()
    if pid == 0:
	# Child.  Exec.
	os.close(0)
	os.close(1)
	os.close(2)
	fd = open("/dev/null", "r")
	os.dup2(stdout_pipe[1], 1)
	os.dup2(stderr_pipe[1], 2)
	# os.closerange(3, 500)
	os.close(stdout_pipe[0]) # Close read end
	os.close(stderr_pipe[0])
	os.execl(cmd, *args)
    else:
	os.close(stdout_pipe[1]) # Close write end
	os.close(stderr_pipe[1])
	out_buf = os.read(stdout_pipe[0], 100000)
	err_buf = os.read(stderr_pipe[0], 100000)
	status = os.waitpid(pid, 0)
	return (os.WEXITSTATUS(status[1]), os.WTERMSIG(status[1]), out_buf, err_buf)


def download_config(code, server, port):
    """
    Contact service and get config blob using one time key
    """
    print "Contacting %s:%s" % (server, port)
    args = ["gsissh", 
	    "-F", "/dev/null", 
	    "-o", "GSSApiTrustDns no",
	    "-o", "ServerAliveInterval 15",
	    "-o", "ServerAliveCountMax 8",
	    server, "-p", str(port),
	    "register", code]
    rc, sig, out, err = run_cmd(GSISSH, args)
    if rc == 255:
	print "Error: Could not connect to server"
	print "---"
	print err
	return None
    if rc != 0:
	print "Error: The server returned an error" 
	print "---"
	print out, err
	return None
    if rc == 0 and sig != 0:
	print "Error: Could not connect to server" 
	print "---"
	print "Exited abnormaly: received signal " + str(sig)
	print out, err
	return None
    return out


def parse_config(config_blob):
    """
    Return Config instance
    """
    data = config_blob
    ret = Config()

    mo = re.search("-----BEGIN RSA PRIVATE KEY-----.*" + \
            "-----END RSA PRIVATE KEY-----\n", data, 
            re.MULTILINE | re.DOTALL)
    if not mo:
        raise Exception("Private key not found")
    ret.key = mo.group()

    mo = re.search("-----BEGIN CERTIFICATE-----.*" + \
            "-----END CERTIFICATE-----\n", data, 
            re.MULTILINE | re.DOTALL)
    if not mo:
        raise Exception("Certificate not found")
    ret.cert = mo.group()

    ret.dns = []
    lines = data.split("\n")
    for l in lines:
        if l.startswith("Allowed User: "):
            dn = l[14:].strip()
            ret.dns.append(dn)

    if not ret.dns:
        raise Exception("No Allowed User found")

    return ret


def copy_file(dst, src):
    buf = open(src).read()
    open(dst, "w").write(buf)


def setup_anon_certs():
    anon_cert = os.path.join(CONFIG_DIR, "anon.cert")
    anon_key = os.path.join(CONFIG_DIR, "anon.key")
    os.chmod(anon_key, 0600)
    os.environ['X509_USER_CERT'] = anon_cert
    os.environ['X509_USER_KEY'] = anon_key


def setup_cert(cert, key):
    print "Installing certificate and key"
    open(SERVICE_CERT, "w").write(cert)
    open(SERVICE_KEY, "w").write(key)
    os.chmod(SERVICE_KEY, 0600)


def setup_gridmap(dns):
    print "Creating %s" % GRIDMAP_FILE
    f = open(GRIDMAP_FILE, "w")
    for dn in dns:
        f.write("\"%s\" %s\n" % (dn, os.environ['USER']))
    f.close()


def main(code, server):
    # Validate safe chars
    mo = re.match("^[0-9a-zA-Z-]+$", code)
    if not mo:
        raise Exception("Invalid Code '%s'" % code)
    mo = re.match("^[0-9a-zA-Z.-]+$", server)
    if not mo:
        raise Exception("Invalid Server '%s'" % server)


    make_dir(X509_CERT_DIR)
    setup_anon_certs()

    # Now talk to service.  Retrieve security info
    config_blob = download_config(code, server, "2223")
    if not config_blob:
        return 1
    config = parse_config(config_blob)
    setup_cert(config.cert, config.key)
    setup_gridmap(config.dns)
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] == "-h":
        print "Usage: setup.py code [server]"
        sys.exit(2)
    code = args[0].strip()
    try:
        server = args[1].strip()
    except IndexError:
        server = "relay.globusonline.org"
    rc = main(code, server)
    if rc == 0:
        print "Done!"
    sys.exit(rc)


