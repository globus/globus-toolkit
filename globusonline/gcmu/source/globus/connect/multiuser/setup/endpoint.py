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
"""
Set up an endpoint defined in /etc/globus-connect-multiuser.conf. Prompts for
username and password to authenticate if they are not in the configuration
file.
"""
import sys
import getopt
import os
import uuid

import globus.connect.multiuser as gcmu
import globus.connect.security as security
from globus.connect.multiuser.setup import Setup

from globusonline.transfer.api_client import TransferAPIClient, TransferAPIError
from urlparse import urlparse

class SetupEndpoint(Setup):
    def __init__(self, **kwargs):
        Setup.__init__(self, **kwargs)
        self.errorcount = 0

    def configure_endpoint(self, force=False):
        endpoint_name = self.conf.get_endpoint_name()
        if endpoint_name is None:
            return

        if force:
            try:
                self.logger.debug("Removing old endpoint definition")
                self.api.endpoint_delete(endpoint_name)
            except:
                pass

        self.logger.debug("Configuring endpoint " + endpoint_name)
        endpoint_public = self.conf.get_endpoint_public()
        endpoint_default_dir = self.conf.get_endpoint_default_dir()

        try:
            (status_code, status_reason, data) = self.api.endpoint(endpoint_name)
            old_default_dir = data.get("default_directory")
            changed = False
            if old_default_dir is not None and \
                    old_default_dir != endpoint_default_dir:
                self.logger.debug("Changing default_directory on endpoint " \
                    "from [%(old)s] to [%(new)s]" % {
                            'old': old_default_dir,
                            'new': endpoint_default_dir
                    })
                data[u'default_directory'] = gcmu.to_unicode(endpoint_default_dir)
                changed = True

            old_public = data.get('public')
            if old_public is not None and old_public != endpoint_public:
                data[u'public'] = endpoint_public
                changed = True

            if changed:
                self.api.endpoint_update(endpoint_name, data)

        except TransferAPIError, e:
            if e.status_code == 404:
                self.logger.debug("endpoint %s does not exist, creating" 
                        %(endpoint_name))
                try:
                    (status_code, status_reason, data) = \
                        self.api.endpoint_create(
                            endpoint_name,
                            default_directory = endpoint_default_dir,
                            public = endpoint_public,
                            is_globus_connect = False,
                            hostname = 'relay-disconnected.globusonline.org')
                    (status_code, status_reason, data) = \
                        self.api.endpoint(endpoint_name)
                except TransferAPIError, e:
                    self.logger.error("endpoint create failed: %s" % \
                        (e.message))
                    self.errorcount += 1
            else:
                self.logger.error("endpoint failed: %s" % (e.message))
                self.errorcount += 1

    def configure_physical_servers(self, reset=False, force=False):
        """
        Add the physical (Grid)FTP server file to the
        endpoints it is associated with in the configuration file. If there 
        """
        server = self.conf.get_gridftp_server()
        if server is not None:
            self.logger.debug("Associating GridFTP servers with endpoints")
            if not(server.startswith("gsiftp://") or server.startswith("ftp://")):
                if ":" not in server:
                    server = server + ":2811"
                server = "gsiftp://" + server
            uri = urlparse(server)

            endpoint_name = self.conf.get_endpoint_name()
            self.logger.debug("Processing " + endpoint_name)
            try:
                (status_code, status_reason, data) = self.api.endpoint(
                        endpoint_name)
                if data is not None:
                    if uri.scheme != 'gsiftp' and uri.scheme != 'ftp':
                        raise Exception("Unknown URI scheme: " + uri.scheme)
                    if ':' in uri.netloc:
                        (host, _, port) = uri.netloc.partition(':')
                        port = int(port)
                    else:
                        host = gcmu.to_unicode(uri.netloc)
                        if uri.scheme == 'ftp':
                            port = 21
                        else:
                            port = 2811
                        server = server + ":" + port

                    new_server = {}
                    new_server[u'DATA_TYPE'] = u'server'
                    new_server[u'uri'] =  gcmu.to_unicode(server)
                    new_server[u'scheme'] =  gcmu.to_unicode(uri.scheme)
                    new_server[u'hostname'] = gcmu.to_unicode(host)
                    new_server[u'port'] = port
                    new_server[u'is_connected'] = True
                    subject = self.conf.get_gridftp_dn()
                    if subject is None and (gcmu.is_local_service(host) \
                            or self.conf.get_gridftp_server_behind_nat()):
                        certpath = self.conf.get_security_certificate_file()
                        if certpath is not None:
                            subject = security.get_certificate_subject(certpath)
                    if subject is not None:
                        new_server[u'subject'] = gcmu.to_unicode(subject)
                    new_server[u'update'] = True

                    if force or reset:
                        servers_filtered = []
                    else:
                        servers_filtered = [x for x in data[u'DATA'] \
                            if x[u'hostname'] != None and
                               x[u'hostname'] !=
                                    u'relay-disconnected.globusonline.org' \
                                    and
                               x[u'uri'] != gcmu.to_unicode(server)]

                    for sf in servers_filtered:
                        sf[u'update'] = True
                    servers_filtered.append(new_server)
                    data['DATA'] = servers_filtered

                    (status_code, status_reason, data) = \
                        self.api.endpoint_update(endpoint_name, data)
            except TransferAPIError, e:
                self.logger.error("Error processing endpoint %s: %s" \
                    % (endpoint_name, e.message))
                self.errorcount += 1

    def configure_myproxy(self):
        myproxy_server = self.conf.get_myproxy_server()
        if myproxy_server is not None:
            if ':' in myproxy_server:
                (host, _, portstr) = myproxy_server.partition(':')
                port = int(portstr)
            else:
                host = myproxy_server
                port = 7512
                myproxy_server = host + ":" + str(port)
                 
            myproxy_dn = self.conf.get_myproxy_dn()
            if myproxy_dn is None:
                if myproxy_dn is None and \
                        (gcmu.is_local_service(myproxy_server) or \
                        self.conf.get_myproxy_server_behind_nat()):
                    certpath = os.path.join(
                            self.conf.get_myproxy_ca_directory(),
                            "cacert.pem")
                    if certpath is not None:
                        try:
                            myproxy_dn = security.get_certificate_subject(certpath)
                        except:
                            self.logger.warning(
                                    "Unable to determine MyProxy service DN.")
                            myproxy_dn = None

            endpoint_name = self.conf.get_endpoint_name()
            try:
                (status_code, status_reason, data) = self.api.endpoint(
                        endpoint_name)
                if data is not None:
                    data[u'myproxy_server'] = gcmu.to_unicode(myproxy_server)
                    if myproxy_dn is not None:
                        data[u'myproxy_dn'] = gcmu.to_unicode(myproxy_dn)
                    (status_code, status_reason, data) = \
                        self.api.endpoint_update(endpoint_name, data)
            except TransferAPIError, e:
                self.logger.error(
                        "Error modifying myproxy of endpoint %s: %s" \
                        % (endpoint_name, e.message))
                self.errorcount += 1


    def configure_oauth(self):
        if self.conf.get_security_authorization_method() == "CILogon":
            oauth_server = "cilogon.org"
            endpoint_name = self.conf.get_endpoint_name()
            try:
                (status_code, status_reason, data) = self.api.endpoint(
                        endpoint_name)
                data[u'myproxy_server'] = None
                data[u'myproxy_dn'] = None
                data[u'oauth_server'] = oauth_server

                (status_code, status_reason, data) = \
                    self.api.endpoint_update(endpoint_name, data)
            except TransferAPIError, e:
                self.logger.error(
                        "Error modifying myproxy of endpoint %s: %s" \
                        % (endpoint_name, e.message))
                self.errorcount += 1

    def configure(self, reset=False, force=False):
        self.logger.info("Configuring Globus Online Endpoint")
        self.configure_endpoint(force=force)
        self.configure_physical_servers(reset=reset, force=force)
        self.configure_myproxy()
        self.configure_oauth()

    def remove_endpoint(self):
        endpoint_name = self.conf.get_endpoint_name()
        try:
            self.logger.debug("Removing old endpoint definition")
            self.api.endpoint_delete(endpoint_name)
        except:
            self.errorcount += 1
            pass
# vim: filetype=python : nospell :
