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
import glob
import getopt

driver_module = None

#defaults
driver = "psycopg2"
database = "newusage"
host = ""
port = ""
user = ""
password = ""
data_directory = os.path.join(
    os.environ['GLOBUS_LOCATION'], 'var', 'usage')
# loads configuration file created by setup script
execfile(
    os.path.join(
        os.environ['GLOBUS_LOCATION'], 'etc', 'globus-usage-tools.conf'))

# Import the configured database driver
exec("import %s" % (driver))
driver_module = eval(driver)

def connect():
    global driver_module
    return driver_module.connect(connect_string())

def connect_string():
    '''
    Construct a dsn from the defined parameters in the configuration
    '''
    connect_str = "dbname=%s" % (database)
    if user != "":
        connect_str += " user=%s" % (user)
    if password != "":
        connect_str += " password=%s" % (password)
    if host != "":
        connect_str += " host=%s" % (host)
    if port != "":
        connect_str += " port=%s" % (port)
    return connect_str
# vim: set ts=4:sw=4:syntax=python
