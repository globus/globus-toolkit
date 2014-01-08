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
"""Remove Globus-related MyProxy server configuration

globus-connect-server-id-cleanup [-h|--help]
globus-connect-server-id-cleanup {-c FILENAME|--config-file=FILENAME}
                                    {-v|--verbose}
                                    {-r PATH|--root=PATH}

The globus-connect-server-id-cleanup command deletes MyProxy service
configuration previously created by running globus-connect-server-id-setup.
It deletes configuration files, stops, and disables the MyProxy server.

If the -r PATH or --root=PATH command-line option is used,
globus-connect-server-id-cleanup will delete MyProxy configuration and
certificates from a subdirectory rooted at PATH instead of /. This means, for
example, that globus-connect-server-id-cleanup deletes MyProxy configuration
files in PATH/etc/myproxy.d.

The following options are available:

-h, --help
                                Display help information
-c FILENAME, --config-file=FILENAME
                                Use configuration file FILENAME instead of
                                /etc/globus-connect-server.conf
-v, --verbose                   Print more information about tasks
-r PATH, --root=PATH            Add PATH as the directory prefix for the
                                configuration files that
                                globus-connect-server-id-cleanup writes
"""

short_usage = """globus-connect-server-id-cleanup [-h|--help]
globus-connect-server-id-cleanup {-c FILENAME|--config-file=FILENAME}
                                    {-v|--verbose}
                                    {-r PATH|--root=PATH}
"""

import getopt
import getpass
import os
import socket
import sys
import time
import traceback

from globusonline.transfer.api_client.goauth import get_access_token, GOCredentialsError
from globusonline.transfer.api_client import TransferAPIClient
from globus.connect.server import get_api
from globus.connect.server.id import ID
from globus.connect.server.configfile import ConfigFile

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
    try:
        opts, arg = getopt.getopt(sys.argv[1:], "hc:vr:",
                ["help", "config-file=", "verbose", "root="])
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
        else:
            print >>sys.stderr, "Unknown option %s" %(o)
            sys.exit(1)

    try:
        os.umask(022)
        conf = ConfigFile(config_file=conf_filename, root=root)
        api = get_api(conf)
        id = ID(config_obj=conf, api=api, debug=debug)
        id.cleanup()
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
