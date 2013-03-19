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
import pkgutil
import ssl
import sys
import time
import uuid

from globus.connect.multiuser.configfile import ConfigFile
import globus.connect.security

from globusonline.transfer.api_client import TransferAPIClient
from globusonline.transfer.api_client import TransferAPIError
from globusonline.transfer.api_client.goauth import get_access_token
from urlparse import urlparse

__path__ = pkgutil.extend_path(__path__, __name__)

class Setup(object):
    logger = logging.getLogger("globus.connect.multiuser.setup")
    handler = logging.StreamHandler()
    logger.addHandler(handler)

    def __init__(self, config_file = None, debug = False, config_obj = False, api=None, force=False):
        if config_obj is None:
            config_obj = ConfigFile(config_file=config_file)

        self.logger = Setup.logger
        if debug:
            Setup.handler.setLevel(logging.DEBUG)
            Setup.logger.setLevel(logging.DEBUG)
        else:
            Setup.handler.setLevel(logging.INFO)
            Setup.logger.setLevel(logging.INFO)
        self.conf = config_obj
        self.debug = debug
        self.force = force

        user = self.conf.get_go_username()
        password = self.conf.get_go_password()

        if api is None:
            self.logger.debug("Acquiring Globus Online Access Token")
            for tries in xrange(1, 10):
                try:
                    auth_result = get_access_token(user, password)
                except ssl.SSLError, e:
                    if "timed out" not in e.args[0]:
                        raise(e)
                    time.sleep(0.5)
            if auth_result is None:
                raise(Exception("Unable to obtain token"))

            api = TransferAPIClient(username=auth_result.username,
                                    goauth=auth_result.token)
        self.api = api

        if self.debug:
            pass #self.api.set_http_connection_debug(True)
        self.errorcount = 0
# vim: filetype=python: nospell:
