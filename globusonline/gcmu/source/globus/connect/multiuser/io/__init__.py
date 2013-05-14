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

import copy
import getopt
import logging
import os
import pkgutil
import platform
import re
import shutil
import sys
import uuid

import globus.connect.security as security
import globus.connect.multiuser as gcmu

from globusonline.transfer.api_client import TransferAPIClient
from globusonline.transfer.api_client import TransferAPIError

class IO(gcmu.GCMU):
    """
    Class to configure a GridFTP server and register it as a Globus Online
    endpoint
    """
    def __init__(self, **kwargs):
        super(IO, self).__init__(**kwargs)
        self.etc_gridftp_d = self.conf.get_etc_gridftp_d()
        self.var_gridftp_d = self.conf.get_var_gridftp_d()
        self.service = "globus-gridftp-server"

        if not os.path.exists(self.etc_gridftp_d):
            os.makedirs(self.etc_gridftp_d, 0755)
        if not os.path.exists(self.var_gridftp_d):
            os.makedirs(self.var_gridftp_d, 0755)

    def setup(self, **kwargs):
        self.logger.debug("ENTER: IO.setup()")

        if not self.is_local_gridftp():
            self.logger.debug("No GridFTP server to configure on this node")

        self.configure_credential(**kwargs)
        self.configure_server(**kwargs)
        self.configure_sharing(**kwargs)
        self.configure_trust_roots(**kwargs)
        self.configure_authorization(**kwargs)
        self.restart(**kwargs)
        self.enable(**kwargs)
        self.bind_to_endpoint(**kwargs)
        self.logger.debug("EXIT: IO.setup()")

    def configure_credential(self, **kwargs):
        """
        Sets up a GridFTP server's certificate and private key.

        Writes a GridFTP configuration fragment to set the certificate and
        key paths in the GridFTP server's environment.
        """
        self.logger.debug("ENTER: IO.configure_credential()")

        (cert, key) = super(IO, self).configure_credential(**kwargs)

        cred_config_file = os.path.join(
                self.var_gridftp_d,
                "globus-connect-multiuser-credential")
        cred_config = open(cred_config_file, "w")

        link_name = os.path.join(
                self.etc_gridftp_d,
                "globus-connect-multiuser-credential")

        if os.path.lexists(link_name):
            os.remove(link_name)

        try:
            try:
                self.logger.debug("Writing GridFTP credential configuration")
                cred_config.write("$X509_USER_CERT \"%s\"\n" % (cert))
                cred_config.write("$X509_USER_KEY \"%s\"\n" % (key))
            except:
                self.logger.error("Error writing GridFTP credential config")
        finally:
            cred_config.close()

        try:
            os.symlink(cred_config_file, link_name)
        except:
            self.logger.error("ERROR creating symlink to GridFTP " +
                    "credential config")

        self.logger.debug("EXIT: IO.configure_credential()")

    def configure_server(self, **kwargs):
        """
        Write a configuration file containing the general GridFTP configuration
        items from the configuration file: IncomingPortRange,
        OutgoingPortRange, DataInterface, and RestrictPaths
        """
        self.logger.debug("ENTER: configure_server()")
        server = self.conf.get_gridftp_server()
        conf_file_name = os.path.join(
                self.var_gridftp_d, "globus-connect-multiuser")
        conf_link_name = os.path.join(
                self.etc_gridftp_d, "globus-connect-multiuser")

        if os.path.lexists(conf_link_name):
            os.remove(conf_link_name)

        self.logger.debug("Creating gridftp configuration")

        conf_file = file(conf_file_name, "w")
        try:
            version = pkgutil.get_data(
                "globus.connect.multiuser",
                "version")
            if version:
                conf_file.write("usage_stats_id GCMU-%s" % (version))
            if ":" in server:
                port = int(server.split(":")[1])
                conf_file.write("port %d\n" % port)
                self.logger.warn(
"""
******************************************************************************
WARNING: You configured your GridFTP server with a custom port.  In order
to override the default GridFTP server port, it may be necessary to edit
the global GridFTP server configuration file at /etc/gridftp.conf, and
comment out the "port" argument.
Change:
port 2811
to
#port 2811

Restart the globus-gridftp-server service if changes are made.
******************************************************************************
""")
            incoming_range = self.conf.get_gridftp_incoming_port_range()
            if incoming_range is not None:
                conf_file.write(
                    "port_range %d,%d\n" \
                    % (incoming_range[0], incoming_range[1]))
            outgoing_range = self.conf.get_gridftp_outgoing_port_range()
            if outgoing_range is not None:
                conf_file.write("$GLOBUS_TCP_SOURCE_RANGE %d,%d\n" \
                    % (outgoing_range[0], outgoing_range[1]))
            data_interface = self.conf.get_gridftp_data_interface()

            if data_interface is None:
                if gcmu.is_ec2():
                    data_interface = gcmu.public_ip()
                elif self.conf.get_gridftp_server_behind_nat():
                    data_interface = server
                    if ":" in data_interface:
                        data_interface = data_interface.split(":")[0]
                    if gcmu.is_private_ip(data_interface):
                        self.logger.warn(
"""
******************************************************************************
WARNING: Your GridFTP server is behind a NAT, but the Server name resolves
to a private IP address. This probably won't work correctly with Globus Online.
To remedy, set the DataInterface option in the [GridFTP] section of the
globus-connect-multiuser.conf file to the public IP address of this GridFTP
server
******************************************************************************
""")

            if data_interface is not None:
                conf_file.write("data_interface %s\n" \
                    % (data_interface))

            rp = self.conf.get_gridftp_restrict_paths()
            if rp is not None:
                conf_file.write("restrict_paths %s\n" % rp)

            os.symlink(conf_file_name, conf_link_name)
        finally:
            conf_file.close()
        self.logger.debug("EXIT: IO.configure_server()")

    def configure_sharing(self, **kwargs):
        """
        Write GridFTP sharing-related configuration items. These are written
        only if Sharing is True in the configuration file. The configuration
        parameters SharingDN, SharingRestrictPaths, and SharingStateDir are
        processed here
        """
        self.logger.debug("ENTER: IO.configure_sharing()")

        conf_file_name = os.path.join(
                self.var_gridftp_d, "globus-connect-multiuser-sharing")
        conf_link_name = os.path.join(
                self.etc_gridftp_d, "globus-connect-multiuser-sharing")

        if os.path.lexists(conf_link_name):
            self.logger.debug("Removing old sharing configuration link")
            os.remove(conf_link_name)

        if not self.conf.get_gridftp_sharing():
            if os.path.exists(conf_file_name):
                self.logger.debug("Removing old sharing configuration file")
                os.remove(conf_file_name)
            self.logger.info("GridFTP Sharing Disabled")
            return

        conf_file = file(conf_file_name, "w")
        try:
            sharing_dn = self.conf.get_gridftp_sharing_dn()
	    conf_file.write("sharing_dn\t\"%s\"\n" % \
                sharing_dn)
            sharing_rp = self.conf.get_gridftp_sharing_restrict_paths()
            if sharing_rp is not None:
                conf_file.write("sharing_rp %s\n" % sharing_rp)
            sharing_dir = self.conf.get_gridftp_sharing_state_dir()
            if sharing_dir is not None:
                conf_file.write("sharing_state_dir %s\n" % sharing_dir)
            sharing_control = self.conf.get_gridftp_sharing_control()
            if sharing_control == False:
                conf_file.write("sharing_control 0\n")
            os.symlink(conf_file_name, conf_link_name)
        finally:
            conf_file.close()
        self.logger.debug("EXIT: IO.configure_sharing()")

    def configure_trust_roots(self, **kwargs):
        """
        Configure the GridFTP server to use the trust roots needed to
        match the definition in the security section of the configuration.
        """
        self.logger.debug("ENTER: IO.configure_trust_roots()")
        # The setup class will populate the trusted CA dir, this class
        # adds the gridftp-specific configuration
        super(IO, self).configure_trust_roots(**kwargs)
        cadir = self.conf.get_security_trusted_certificate_directory()

        conf_file_name = os.path.join(
                self.var_gridftp_d, "globus-connect-multiuser-trust-roots")
        conf_link_name = os.path.join(
                self.etc_gridftp_d, "globus-connect-multiuser-trust-roots")

        if os.path.lexists(conf_link_name):
            self.logger.debug("Removing old trust roots configuration link")
            os.remove(conf_link_name)

        conf_file = file(conf_file_name, "w")
        try:
            conf_file.write("$X509_CERT_DIR \"%s\"\n" % (cadir))
            os.symlink(conf_file_name, conf_link_name)
        finally:
            conf_file.close()
        self.logger.debug("EXIT: IO.configure_sharing()")


    def configure_authorization(self, **kwargs):
        method = self.conf.get_security_authorization_method()

        conf_file_name = os.path.join(
                self.var_gridftp_d,
                "globus-connect-multiuser-authorization")
        conf_link_name = os.path.join(
                self.etc_gridftp_d,
                "globus-connect-multiuser-authorization")
        server = self.conf.get_gridftp_server()

        if os.path.lexists(conf_link_name):
            os.remove(conf_link_name)

        if method == "MyProxyGridmapCallout":
            return self.configure_gridmap_verify_myproxy_callout(
                    conf_file_name, conf_link_name, **kwargs)
        elif method == "CILogon":
            return self.configure_cilogon(
                    conf_file_name, conf_link_name, **kwargs)

    def configure_gridmap_verify_myproxy_callout(self, conf_file_name, conf_link_name, **kwargs):
        self.logger.debug("ENTER: configure_gridmap_verify_myproxy_callout()")

        conf_file = file(conf_file_name, "w")
        try:
            conf_file.write("$GSI_AUTHZ_CONF \"%s\"\n" % (
                os.path.join(
                    self.conf.root, "etc",
                    "gridmap_verify_myproxy_callout-gsi_authz.conf"
                    )
                )
            )
            myproxy_certpath = None
            myproxy_signing_policy = None
            myproxy_ca_dn = self.conf.get_myproxy_ca_subject_dn()
            myproxy_server = self.conf.get_myproxy_server()
            if myproxy_ca_dn is None and \
                    myproxy_server is not None and \
                    self.is_local_myproxy():
                myproxy_ca_dir = self.conf.get_myproxy_ca_directory()
                myproxy_ca_dn = security.get_certificate_subject(
                        os.path.join(myproxy_ca_dir, "cacert.pem"))
            else:
                # Assume the CA name is the same as the MyProxy server's
                # subject
                myproxy_ca_dn = self.conf.get_myproxy_dn()
                if myproxy_ca_dn is None:
                    myproxy_ca_dn = self.get_myproxy_dn_from_server()

            cadir = self.conf.get_security_trusted_certificate_directory()
            self.logger.debug("MyProxy CA DN is " + str(myproxy_ca_dn))
            self.logger.debug("CA dir is " + str(cadir))

            if self.is_local_myproxy():
                myproxy_certpath = os.path.join(
                    self.conf.get_myproxy_ca_directory(),
                    "cacert.pem")
                myproxy_signing_policy = os.path.join(
                    self.conf.get_myproxy_ca_directory(),
                    "signing-policy")
            elif myproxy_ca_dn is not None:
                self.logger.debug("Looking for MyProxy CA cert in " + cadir)
                for certfile in os.listdir(cadir):
                    certpath = os.path.join(cadir, certfile)
                    if certfile[-2:] == '.0':
                        self.logger.debug("Checking to see if " + certfile + " matches MyProxyDN")
                        if security.get_certificate_subject(
                                certpath) == myproxy_ca_dn:
                            myproxy_certpath = certpath
                            (myproxy_signing_policy, _) = \
                                    os.path.splitext(
                                            myproxy_certpath)
                            myproxy_signing_policy += \
                                    ".signing_policy"
                            break

            if myproxy_certpath is None:
                raise Exception("ERROR: Unable to determine " +
                    "path to MyProxy CA certificate, set " + \
                    "CaCert option in MyProxy section of config.\n")

            myproxy_ca_hash = security.get_certificate_hash(
                    myproxy_certpath)
                    
            cadir = \
                self.conf.get_security_trusted_certificate_directory()
            installed_cert = os.path.join(
                    cadir, myproxy_ca_hash + ".0")
            installed_signing_policy = os.path.join(
                    cadir, myproxy_ca_hash + ".signing_policy")
            if not os.path.exists(installed_cert):
                self.logger.error("MyProxy CA not installed in trusted CA dir")
            if not os.path.exists(installed_signing_policy):
                self.logger.error("MyProxy CA signing policy not installed " + \
                    "in trusted CA dir")
            
            conf_file.write(
                    "$GLOBUS_MYPROXY_CA_CERT \"%s\"\n" %
                    installed_cert)
            os.symlink(conf_file_name, conf_link_name)
        finally:
            conf_file.close()
        self.logger.debug("EXIT: configure_gridmap_verify_myproxy_callout()")

    def configure_cilogon(self, conf_file_name, conf_link_name, **kwargs):
        self.logger.debug("ENTER: IO.configure_cilogon()")

        conf_file = file(conf_file_name, "w")
        try:
            cadir = self.conf.get_security_trusted_certificate_directory()
            ca = pkgutil.get_data(
                    "globus.connect.security",
                    "cilogon-basic.pem")
            signing_policy = pkgutil.get_data(
                    "globus.connect.security",
                    "cilogon-basic.signing_policy")
            cahash = security.get_certificate_hash_from_data(ca)

            idp = self.conf.get_security_cilogon_identity_provider()

            security.install_ca(cadir, ca, signing_policy)

            conf_file.write(
                    "$GLOBUS_MYPROXY_CA_CERT \"%s\"\n" %
                    (os.path.join(cadir, cahash + ".0")))
            conf_file.write(
                    "$GLOBUS_MYPROXY_AUTHORIZED_DN " +
                    "\"/DC=org/DC=cilogon/C=US/O=%s\"\n" % (idp))
            conf_file.write(
                    "$GSI_AUTHZ_CONF \"%s\"\n" % (
                            os.path.join(
                            self.conf.root, "etc",
                            "gridmap_eppn_callout-gsi_authz.conf")))
            os.symlink(conf_file_name, conf_link_name)
        finally:
            conf_file.close()
        self.logger.debug("EXIT: IO.configure_cilogon()")

    def cleanup(self, **kwargs):
        for name in os.listdir(self.etc_gridftp_d):
            if name.startswith("globus-connect-multiuser") \
                        or name.startswith("gcmu"):
                os.remove(os.path.join(self.etc_gridftp_d, name))
        endpoint_name = self.conf.get_endpoint_name()
        server = self.conf.get_gridftp_server()
        port = 2811
        if "://" in server:
            server = server.split("://",1)[1]
        if ":" in server:
            (server, port) = server.split(":",1)[0]

        if kwargs.get("delete"):
            self.api.endpoint_delete(endpoint_name)
        else:
            (status_code, status_reason, data) = \
                self.api.endpoint(endpoint_name)
            servers_filtered = [x for x in data[u'DATA'] \
                if x[u'hostname'] != None and
                   x[u'uri'] != gcmu.to_unicode(server)]
            data[u'DATA'] = servers_filtered
            self.api.endpoint_update(endpoint_name, data)

    def bind_to_endpoint(self, **kwargs):
        """
        Adds this gridftp server to the endpoint named in the configuration
        file. If force=True is passed, then the endpoint is deleted prior
        to binding this gridftp server. If reset=True is passed, then
        all other GridFTP servers will be removed from this endpoint before
        adding this one.
        """
        self.logger.debug("ENTER: IO.bind_to_endpoint()")
        endpoint_name = self.conf.get_endpoint_name()

        if endpoint_name is None:
            return

        if kwargs.get('force'):
            try:
                self.logger.debug("Removing old endpoint definition")
                self.api.endpoint_delete(endpoint_name)
            except:
                pass

        self.logger.debug("Configuring endpoint " + endpoint_name)
        endpoint_public = self.conf.get_endpoint_public()
        endpoint_default_dir = self.conf.get_endpoint_default_dir()

        server = self.conf.get_gridftp_server()
        scheme = "gsiftp"
        port = 2811
        hostname = None

        if "://" in server:
            (scheme, server) = server.split("://", 1)

        if ":" in server:
            (hostname, port_s) = server.split(":", 1)
            port = int(port_s)
        else:
            hostname = server

        myproxy_server = None
        myproxy_dn = None
        oauth_server = self.conf.get_oauth_server()
        if oauth_server is None:
            myproxy_server = self.conf.get_myproxy_server()
            myproxy_dn = self.conf.get_myproxy_dn()

        if myproxy_server is not None:
            myproxy_server = gcmu.to_unicode(myproxy_server)
        if myproxy_dn is not None:
            myproxy_dn = gcmu.to_unicode(myproxy_dn)
        if oauth_server is not None:
            oauth_server = gcmu.to_unicode(oauth_server)

        new_gridftp_server = {
                u'DATA_TYPE': u'server',
                u'uri': gcmu.to_unicode(server),
                u'scheme': gcmu.to_unicode(scheme),
                u'hostname': gcmu.to_unicode(hostname),
                u'port': port,
                u'is_connected': True,
                u'subject': gcmu.to_unicode(security.get_certificate_subject(self.conf.get_security_certificate_file())),
                u'update': True,
        }

        try:
            (status_code, status_reason, data) = \
                self.api.endpoint(endpoint_name)
            old_default_dir = data.get("default_directory")
            changed = False
            if old_default_dir is not None and \
                    old_default_dir != endpoint_default_dir:
                self.logger.debug("Changing default_directory on endpoint " \
                    "from [%(old)s] to [%(new)s]" % {
                            'old': old_default_dir,
                            'new': endpoint_default_dir
                    })
                data[u'default_directory'] = \
                        gcmu.to_unicode(endpoint_default_dir)

            old_public = data.get('public')
            if old_public is not None and old_public != endpoint_public:
                data[u'public'] = endpoint_public

            if kwargs.get("reset"):
                servers = [new_gridftp_server]
            else:
                servers_filtered = [x for x in data[u'DATA'] \
                    if x[u'hostname'] != None and
                       x[u'hostname'] != \
                            u'relay-disconnected.globusonline.org' and \
                       x[u'uri'] != gcmu.to_unicode(server)]
                servers_filtered.append(new_gridftp_server)

            data[u'myproxy_server'] = myproxy_server
            data[u'myproxy_dn'] = myproxy_dn
            data[u'oauth_server'] = oauth_server

            self.api.endpoint_update(endpoint_name, data)
        except TransferAPIError, e:
            if e.status_code == 404:
                self.logger.debug("endpoint %s does not exist, creating" 
                        %(endpoint_name))
                try:
                    (status_code, status_reason, data) = \
                        self.api.endpoint_create(
                            endpoint_name,
                            public = endpoint_public,
                            is_globus_connect = False,
                            hostname=new_gridftp_server[u'hostname'],
                            scheme=new_gridftp_server[u'scheme'],
                            port=new_gridftp_server[u'port'],
                            subject=new_gridftp_server[u'subject'],
                            myproxy_server=myproxy_server,
                            myproxy_dn=myproxy_dn,
                            oauth_server=oauth_server)
                    (status_code, status_reason, data) = \
                        self.api.endpoint(endpoint_name)
                except TransferAPIError, e:
                    self.logger.error("endpoint create failed: %s" % \
                        (e.message))
                    self.errorcount += 1
            else:
                self.logger.error("endpoint failed: %s" % (e.message))
                self.errorcount += 1
        self.logger.debug("EXIT: IO.bind_to_endpoint()")

# vim: filetype=python:
