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
"""Clean up MyProxy OAuth server configuration

globus-connect-multiuser-web-cleanup [-h|--help]
globus-connect-multiuser-web-cleanup {-c FILENAME|--config-file=FILENAME}
                                     {-v|--verbose}
                                     {-r PATH|--root=PATH}

The globus-connect-multiuser-web-cleanup command deletes MyProxy OAuth service
configuration previously created by running globus-connect-multiuser-web-setup.
It deletes configuration files, stops, and disables the MyProxy server.

If the -r PATH or --root=PATH command-line option is used,
globus-connect-multiuser-web-cleanup will delete MyProxy configuration in a
subdirectory rooted at PATH instead of /. This means, for example, that
globus-connect-multiuser-web-cleanup deletes MyProxy OAuth configuration files
in PATH/etc/apache2 or PATH/etc/httpd.

The following options are available:

-h, --help                          Display help information
-c FILENAME, --config-file=FILENAME Use configuration file FILENAME instead of /etc/globus-connect-multiuser.conf
-v, --verbose                       Print more information about tasks
-r PATH, --root=PATH                Add PATH as the directory prefix for the
                                    configuration files that
                                    globus-connect-multiuser-web-cleanup writes
"""

short_usage = """globus-connect-multiuser-web-cleanup [-h|--help]
globus-connect-multiuser-web-cleanup {-c FILENAME|--config-file=FILENAME}
                                     {-v|--verbose}
                                     {-r PATH|--root=PATH}
"""

import getopt
import getpass
import socket
import sys
import time

from globusonline.transfer.api_client.goauth import get_access_token, GOCredentialsError
from globusonline.transfer.api_client import TransferAPIClient
from globus.connect.multiuser import get_api
from globus.connect.multiuser.web import Web
from globus.connect.multiuser.configfile import ConfigFile

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
        socket.setdefaulttimeout(300)

        conf = ConfigFile(config_file=conf_filename, root=root)
        api = get_api(conf)
        web = Web(config_obj=conf, api=api, debug=debug)
        web.cleanup()
    except KeyboardInterrupt, e:
        print "Aborting..."
        sys.exit(1)

# vim: filetype=python:
