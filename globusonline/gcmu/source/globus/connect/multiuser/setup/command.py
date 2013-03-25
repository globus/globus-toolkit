#! /usr/bin/python

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

import getopt
import socket
import sys

import globus.connect.multiuser.setup

from globus.connect.multiuser.setup.service \
    import SetupMyProxyService, SetupGridFtpService
from globus.connect.multiuser.configfile import ConfigFile
from globus.connect.multiuser.setup.endpoint import SetupEndpoint

def usage(short=False, outstream=sys.stdout):
    if short:
        print >>outstream, "globus-connect-multiuser-setup -h | [OPTIONS]"
    else:
        print >>outstream, """globus-connect-multiuser-setup [OPTIONS]
Options:
  -c | --config-file FILENAME           Read configuration from FILENAME
                                        instead of
                                        /etc/globus-connect-multiuser.conf
  -v | --verbose                        Print debug information while
                                        configuring services and endpoint
  -g | --gridftp-config                 Configure a gridftp server
  -m | --myproxy-config                 Configure a myproxy server
  -e | --endpoint-config                Configure a Globus Online endpoint
  -r | --root PATH                      Write configuration to a directory 
                                        tree rooted at PATH instead of /
  -s | --reset-endpoint                 Removes all GridFTP servers from
                                        the endpoint and configures it to
                                        only use the GridFTP server in the
                                        configuration file
  -d | --delete-endpoint                Delete any existing endpoint definition
                                        for the endpoint in the configuration
                                        file and don't configure any services
  -u | --unconfigure                    Unconfigure services
  -h | --help                           Print this message


If any of -g, -m, or -e (or their long equivalents) are included on the
command-line, then only those services will be configured. Otherwise, all
services which are set up in the configuration file will be configured."""

def main(args):
    conf = None
    force = False
    try:
        opts, arg = getopt.getopt(args, "c:vgmer:uhsd",
                ["config-file=", "verbose",
                 "gridftp-config", "myproxy-config", "endpoint-config",
                 "root=", "unconfigure", "help",
                 "reset-endpoint", "delete-endpoint"])
    except getopt.GetoptError, e:
        print >>sys.stderr, "Invalid option " + e.opt
        usage(short=True, outstream=sys.stderr)
        sys.exit(1)

    do_gridftp = False
    do_myproxy = False
    do_endpoint = False
    do_any = False
    reset_endpoint = False
    remove_endpoint = False
    unconfigure = False
    root = '/'
    debug = False
    for (o, val) in opts:
        if o == '-c' or o == "--config-file":
            conf = val
        elif o == '-v' or o == "--verbose":
            debug = True
        elif o == '-g' or o == "--gridftp-config":
            do_gridftp = True
            do_any = True
        elif o == '-m' or o == "--myproxy-config":
            do_myproxy = True
            do_any = True
        elif o == '-e' or o == "--endpoint-config":
            do_endpoint = True
            do_any = True
        elif o == '-f' or o == "--force":
            force = True
        elif o == '-r' or o == "--root":
            root = val
        elif o == '-u' or o == "--unconfigure":
            unconfigure = True
        elif o == '-s' or o == "--reset-endpoint":
            reset_endpoint = True
        elif o == '-d' or o == "--delete-endpoint":
            remove_endpoint = True
        elif o == '-h' or o == "--help":
            usage()
            sys.exit(0)
        else:
            print "Unknown option %s" %(o)
            sys.exit(1)

    socket.setdefaulttimeout(300)
    # Default to do all
    if do_any is False:
        do_gridftp = True
        do_myproxy = True
        do_endpoint = True

    conf = ConfigFile(config_file=conf, root=root)
    errorcount = 0
    api = None

    if remove_endpoint:
        endpoint_setup = SetupEndpoint(
                config_obj=conf, debug=debug, api=api)
        endpoint_setup.remove_endpoint()
        errorcount += endpoint_setup.errorcount
    elif unconfigure:
        if do_gridftp:
            gridftp_setup = SetupGridFtpService(
                    config_obj=conf, debug=debug, api=api)
            gridftp_setup.unconfigure()
            gridftp_setup.restart()
            api = gridftp_setup.api
            errorcount += gridftp_setup.errorcount

        if do_myproxy:
            myproxy_setup = SetupMyProxyService(
                    config_obj=conf, debug=debug, api=api)
            myproxy_setup.unconfigure()
            myproxy_setup.restart()
            api = myproxy_setup.api
    else:
        if do_myproxy:
            myproxy_setup = SetupMyProxyService(
                    config_obj=conf, debug=debug, api=api)
            myproxy_setup.configure(force=force)
            myproxy_setup.enable()
            myproxy_setup.restart()
            api = myproxy_setup.api
            errorcount += myproxy_setup.errorcount

        if do_gridftp:
            gridftp_setup = SetupGridFtpService(
                    config_obj=conf, debug=debug, api=api)
            gridftp_setup.configure(force=force)
            gridftp_setup.enable()
            gridftp_setup.restart()
            errorcount += gridftp_setup.errorcount

        if do_endpoint:
            endpoint_setup = SetupEndpoint(
                    config_obj=conf, debug=debug, api=api)
            endpoint_setup.configure(reset=reset_endpoint, force=force)
            errorcount += endpoint_setup.errorcount

    return errorcount
    
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
# vim: filetype=python: nospell:
