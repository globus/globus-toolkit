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

from myproxyoauth.database import init_db

init_db()

import logging, sys
import pkgutil
logging.basicConfig(filename="/tmp/wsgi.log", level=logging.DEBUG)

__path__ = pkgutil.extend_path(__path__, __name__)

class MyProxyOAuth(object):
    logger = logging.getLogger()
    def __init__(self):
        self.routes = dict()
        self.teardown_request_func = None
        self.logger = MyProxyOAuth.logger

    def __call__(self, environ, start_response):
        path_info = environ.get("PATH_INFO")
        method = environ.get("REQUEST_METHOD")

        route = method + ":" + path_info
        self.logger.debug("route is " + route)
        if route in self.routes:
            self.logger.debug("route is present")
            exc = None
            try:
                return self.routes[route](environ, start_response)
            except Exception, e:
                exc = e
                headers = [("Content-Type", "text/plain")]
                response = "500 Internal Server Error"
                #start_response(headers, response)
                return [str(e)]
            finally:
                if self.teardown_request_func is not None:
                    self.teardown_request_func(exception=e)
        else:
            try:
                headers = [("Content-Type", "text/plain")]
                response = "404 Not Found"
                start_response(response, headers)
                return [response]
            finally:
                if self.teardown_request_func is not None:
                    self.teardown_request_func()

    def route(self, path, methods=["GET"]):
        def decorator(func):
            for m in methods:
                self.routes[m + ":" + path] = func
        return decorator

    def teardown_request(self, func):
        def decorator():
            self.teardown_request_func = func
        return decorator

application = MyProxyOAuth()

import myproxyoauth.views
# vim: filetype=python: nospell:
