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
import sys

import gcmu.setup

from gcmu.setup.service import SetupMyProxyService, SetupGridFtpService
from gcmu.setup.endpoint import SetupEndpoint

def main(args):
    gcmu_conf = None
    force = False
    opts, arg = getopt.getopt(args, "c:dgmefr:h")
    do_gridftp = False
    do_myproxy = False
    do_endpoint = False
    do_any = False
    unconfigure = False
    root = '/'
    debug = False
    for (o, val) in opts:
        if o == '-c':
            gcmu_conf = val
        elif o == '-d':
            debug = True
        elif o == '-g':
            do_gridftp = True
            do_any = True
        elif o == '-m':
            do_myproxy = True
            do_any = True
        elif o == '-e':
            do_endpoint = True
            do_any = True
        elif o == '-f':
            force = True
        elif o == '-r':
            root = val
        elif o == '-u':
            unconfigure = True
        elif o == '-h':
            print "gcmu-setup [-c CONF] [-g|-m|-d|-f] [-r ROOT] -h"
            sys.exit(0)
        else:
            print "Unknown option %s" %(o)
            sys.exit(1)

    # Default to do all
    if do_any is False:
        do_gridftp = True
        do_myproxy = True
        do_endpoint = True

    conf = gcmu.configfile.ConfigFile(config_file=gcmu_conf, root=root)
    errorcount = 0
    api = None

    if unconfigure:
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
            myproxy_setup.restart()
            api = myproxy_setup.api
            errorcount += myproxy_setup.errorcount

        if do_gridftp:
            gridftp_setup = SetupGridFtpService(
                    config_obj=conf, debug=debug, api=api)
            gridftp_setup.configure(force=force)
            gridftp_setup.restart()
            errorcount += gridftp_setup.errorcount

        if do_endpoint:
            endpoint_setup = SetupEndpoint(
                    config_obj=conf, debug=debug, api=api)
            endpoint_setup.configure(force=force)
            errorcount += endpoint_setup.errorcount

    return errorcount
    
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
# vim: filetype=python: nospell:
