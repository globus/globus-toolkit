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

import os
import sys

# EPEL 6 has a version of jinja2 which works with flask, unlike the
# one in the core rhel/centos/etc repo. This forces that one into
# the path before the normal one
epel_jinja2_egg = "/usr/lib/python2.6/site-packages/Jinja2-2.6-py2.6.egg"
if os.path.exists(epel_jinja2_egg):
    sys.path.insert(0, epel_jinja2_egg)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

sys.path.insert(0, BASE_DIR)

from myproxyoauth import application
