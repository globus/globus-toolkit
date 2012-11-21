#! /usr/bin/env python

# Copyright 1999-2009 University of Chicago
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

import os
import sys

class UsageConfig(object):
    def __init__(self, path=None):
        #defaults
        self.driver = ""
        self.database = "newusage"
        self.host = ""
        self.port = ""
        self.user = ""
        self.password = ""
        self.data_directory = os.path.sep + os.path.join(
            'var', 'lib', 'globus', 'usage')
        self.driver_module = None

        # if there's no path given to this program, look in 
        # /etc/globus/usage-tools.conf and if that's not there
        # $PREFIX/etc/globus/usage-tools.conf
        if path is None:
            path = os.path.sep + os.path.join(
                'etc', 'globus', 'usage-tools.conf')
            if os.path.exists(path):
                execfile(path)
            else:
                exe = sys.argv[0]
                if sbindir != '':
                    sbindir = os.path.dirname(exe)
                    prefix = os.path.dirname(sbindir)
                    path = os.path.join(prefix,
                        "etc", "globus", "usage-tools.conf")
                    if os.path.exists(path):
                        execfile(path)
        elif os.path.exists(path):
            execfile(path)

        if vars().has_key('driver'):
            self.driver = driver
        if vars().has_key('database'):
            self.database = database
        if vars().has_key('host'):
            self.host = host
        if vars().has_key('port'):
            self.port = port
        if vars().has_key('user'):
            self.user = user
        if vars().has_key('password'):
            self.password = password
        if vars().has_key('data_directory'):
            self.data_directory = data_directory

        # Import the configured database driver
        if self.driver != "":
            exec("import %s" % (self.driver))
            self.driver_module = eval(self.driver)

    def connect(self):
        return self.driver_module.connect(self.connect_string())

    def connect_string(self):
        '''
        Construct a dsn from the defined parameters in the configuration
        '''
        connect_str = "dbname=%s" % (self.database)
        if self.user != "":
            connect_str += " user=%s" % (self.user)
        if self.password != "":
            connect_str += " password=%s" % (self.password)
        if self.host != "":
            connect_str += " host=%s" % (self.host)
        if self.port != "":
            connect_str += " port=%s" % (self.port)
        return connect_str

# vim: set ts=4:sw=4:syntax=python
