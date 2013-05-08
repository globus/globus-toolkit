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
"""Remove GridFTP, MyProxy, and OAuth configuration and remove it from a Globus
Online endpoint

globus-connect-multiuser-cleanup [-h|--help]
globus-connect-multiuser-cleanup {-c FILENAME|--config-file=FILENAME}
                                 {-v|--verbose}
                                 {-r PATH|--root=PATH}
                                 {-d|--delete-endpoint}

The globus-connect-multiuser-cleanup command deletes the GridFTP, MyProxy and
OAuth service configurations previously created by running
globus-connect-multiuser-setup and removes the GridFTP server from a Globus
Online endpoint. It deletes configuration files, stops, and disables the
services.

If the -d or --delete-endpoint command-line option is used,
globus-connect-multiuser-io-cleanup removes the endpoint named in the
configuration file as well as cleaning up
globus-connect-multiuser-setup-generated configuration files.

If the -r PATH or --root=PATH command-line option is used,
globus-connect-multiuser-cleanup will write its GridFTP configuration and
certificates in a subdirectory rooted at PATH instead of /. This means, for
example, that globus-connect-multiuser-cleanup deletes GridFTP configuration
files in PATH/etc/gridftp.d.

The following options are available:

-h, --help                          Display help information
-c FILENAME, --config-file=FILENAME Use configuration file FILENAME instead of
                                    /etc/globus-connect-multiuser.conf
-v, --verbose                       Print more information about tasks
-r PATH, --root=PATH                Add PATH as the directory prefix for the
                                    configuration files that
                                    globus-connect-multiuser-io-cleanup writes
-d, --delete-endpoint               Delete the Globus Online endpoint
"""

short_usage = """globus-connect-multiuser-cleanup [-h|--help]
globus-connect-multiuser-cleanup {-c FILENAME|--config-file=FILENAME}
                                 {-v|--verbose}
                                 {-r PATH|--root=PATH}
                                 {-d|--delete-endpoint}
"""

import getopt
import getpass
import socket
import ssl
import sys
import time

from globus.connect.multiuser import get_api
from globusonline.transfer.api_client import TransferAPIClient
from globus.connect.multiuser.io import IO
from globus.connect.multiuser.id import ID
from globus.connect.multiuser.web import Web
from globus.connect.multiuser.configfile import ConfigFile

def usage(short=False, outstream=sys.stdout):
    if short:
        print >>outstream, short_usage
    else:
        print >>outstream, __doc__

if __name__ == "__main__":
    try:
        conf_filename = None
        api = None
        force = False
        debug = False
        root = "/"
        delete = False
        try:
            opts, arg = getopt.getopt(sys.argv[1:], "hc:vr:d",
                    ["help", "config-file=", "verbose", "root=", "delete-endpoint"])
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
            elif o in ['-d', '--delete-endpoint']:
                delete = True
            else:
                print >>sys.stderr, "Unknown option %s" %(o)
                sys.exit(1)

        conf = ConfigFile(config_file=conf_filename, root=root)
        api = get_api(conf)
        io = IO(config_obj=conf, api=api, debug=debug)
        id = ID(config_obj=conf, api=api, debug=debug)
        web = Web(config_obj=conf, api=api, debug=debug)
        web.cleanup()
        io.cleanup(delete=delete)
    except KeyboardInterrupt, e:
        print "Aborting..."
        sys.exit(1)

# vim: filetype=python:
