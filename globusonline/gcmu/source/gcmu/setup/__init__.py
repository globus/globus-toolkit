# Copyright 2010-2013 University of Chicago
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
import logging
import os
import sys
import uuid
import pkgutil

import gcmu.configfile
import gcmu.security
from gcmu.fetchcreds import FetchCreds as GCMUFetchCreds

from globusonline.transfer.api_client import TransferAPIClient
from globusonline.transfer.api_client import TransferAPIError
from globusonline.transfer.api_client.goauth import get_access_token
from urlparse import urlparse

__path__ = pkgutil.extend_path(__path__, __name__)

class Setup(object):
    def __init__(self, config_file = None, debug = False, config_obj = False, api=None, force=False):
        if config_obj is None:
            config_obj = gcmu.configfile.ConfigFile(config_file=config_file)

        self.logger = logging.getLogger("gcmu")
        handler = logging.StreamHandler()
        if debug:
            handler.setLevel(logging.DEBUG)
            self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(handler)
        self.conf = config_obj
        self.debug = debug
        self.force = force

        user = self.conf.get_go_username()
        password = self.conf.get_go_password()

        if api is None:
            self.logger.debug("Acquiring GO Access Token")
            auth_result = get_access_token(user, password)

            api = TransferAPIClient(username=auth_result.username,
                                    goauth=auth_result.token)
        self.api = api

        if self.debug:
            pass #self.api.set_http_connection_debug(True)
        self.errorcount = 0

# vim: set filetype=python:
