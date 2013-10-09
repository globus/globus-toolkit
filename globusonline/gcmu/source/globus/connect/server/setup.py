#!/usr/bin/python
# Copyright 2012-2013 University of Chicago
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Configure a MyProxy, OAuth, and GridFTP server and create a Globus Online endpoint

globus-connect-server-setup [-h|--help]
globus-connect-server-setup {-c FILENAME|--config-file=FILENAME} {-v|--verbose} {-r PATH|--root=PATH} {-s|--reset-endpoint}

The globus-connect-server-setup command combines the functionality of
globus-connect-server-io-setup, globus-connect-server-id-setup, and
globus-connect-server-web-setup to configure a system to act as a GridFTP
server, MyProxy ID server, and OAuth server.It also registers the GridFTP
server as a Globus Online endpoint. Depending on features enabled in the
configuration file, this process will include fetching a service credential
from the Globus Connect CA, writing GridFTP configuration files in the
/etc/gridftp.d/ directory, adding trusted certificates to the GridFTP server's
trust roots, restarting the GridFTP server, enabling the GridFTP server to
start at boot, and creating or modifying an endpoint to point to this server.

If the -s or --reset-endpoint command-line option is used,
globus-connect-server--setup removes all other GridFTP servers associated
with the endpoint before adding this server, if the endpoint already exists.
Otherwise, globus-connect-server-setup adds this server to the list of
servers associated with the endpoint.

If the -r PATH or --root=PATH command-line option is used,
globus-connect-server-setup will write its GridFTP and MyProxy configuration
files and certificates in a subdirectory rooted at PATH instead of /. This
means, for example, that globus-connect-server-setup writes GridFTP
configuration files in PATH/etc/gridftp.d.

The following options are available:

-h, --help                          Display help information
-c FILENAME, --config-file=FILENAME Use configuration file FILENAME instead of
                                    /etc/globus-connect-server.conf
-v, --verbose                       Print more information about tasks
-r PATH, --root=PATH                Add PATH as the directory prefix for the
                                    configuration files that
                                    globus-connect-server-io-setup writes
-s, --reset-endpoint                Remove all other GridFTP servers from this
                                    endpoint before adding this one"""

short_usage = """globus-connect-server-setup [-h|--help]
globus-connect-server-setup {-c FILENAME|--config-file=FILENAME}
                               {-v|--verbose}
                               {-r PATH|--root=PATH}
                               {-s|--reset-endpoint}"""
import getopt
import socket
import os
import sys
import traceback

from globus.connect.server.configfile import ConfigFile
from globus.connect.server import get_api
from globus.connect.server.id import ID
from globus.connect.server.io import IO
from globus.connect.server.web import Web

def usage(short=False, outstream=sys.stdout): 
    if short: 
        print >>outstream, short_usage 
    else: 
        print >>outstream, __doc__ 

if __name__ == "__main__":
    conf_filename = None
    api = None
    force = False
    debug = False
    root = "/"
    reset = False
    try:
        opts, arg = getopt.getopt(sys.argv[1:], "hc:vr:s",
                ["help", "config-file=", "verbose", "root=", "reset-endpoint"])
    except getopt.GetoptError, e:
        print >>sys.stderr, "Invalid option " + e.opt
        usage(short=True, outstream=sys.stderr)
        sys.exit(1)

    if len(arg) > 0:
        print >>sys.stderr, "Unexpected argument(s) " + " ".join(arg)
        sys.exit(1)

    for (o, val) in opts:
        if o in ['-h', '--help']:
            usage()
            sys.exit(0)
        elif o in ['-c', '--config-file']:
            conf_filename = val
        elif o in ['-v',  '--verbose']:
            debug = True
        elif o in ['-r', '--root']:
            root = val
        elif o in ['-s', '--reset-endpoint']:
            reset = True
        else:
            print >>sys.stderr, "Unknown option %s" %(o)
            sys.exit(1)

    try:
        os.umask(022)
        socket.setdefaulttimeout(300)

        conf = ConfigFile(config_file=conf_filename, root=root)
        api = get_api(conf)
        id = ID(config_obj=conf, api=api, debug=debug)
        web = Web(config_obj=conf, api=api, password=api.password, debug=debug)
        io = IO(config_obj=conf, api=api, debug=debug)
        id.setup()
        web.setup()
        io.setup(reset=reset)
        sys.exit(io.errorcount + id.errorcount + web.errorcount)
    except KeyboardInterrupt, e:
        print "Aborting..."
        sys.exit(1)
    except Exception, e:
        if debug:
            traceback.print_exc(file=sys.stderr)
        else:
            print str(e)
        sys.exit(1)

# vim: filetype=python:
