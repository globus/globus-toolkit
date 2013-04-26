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
from globus.connect.security.fetchcreds import FetchCreds
from globus.connect.multiuser.setup import Setup
import globus.connect.multiuser as gcmu

from globusonline.transfer.api_client import TransferAPIClient
from globusonline.transfer.api_client import TransferAPIError
from urlparse import urlparse

from subprocess import Popen, PIPE

class SetupService(Setup):
    def __init__(self, **kwargs):
        super(SetupService, self).__init__(**kwargs)

    def is_local_gridftp(self):
        server = self.conf.get_gridftp_server()
        return gcmu.is_local_service(server) or \
            (server is not None and self.conf.get_gridftp_server_behind_nat())

    def is_local_myproxy(self):
        server = self.conf.get_myproxy_server()
        return gcmu.is_local_service(server) or \
            (server is not None and self.conf.get_myproxy_server_behind_nat())

    def configure_security(self, force=False):
        fetch_creds = self.conf.get_security_fetch_credential_from_relay()

        # Do nothing if we don't want to use GlobusOnline relay creds
        if not fetch_creds:
            return

        cert = self.conf.get_security_certificate_file()
        key = self.conf.get_security_key_file()

        self.logger.debug("Creating directory to hold service certificates")
        if not os.path.exists(os.path.dirname(cert)):
            os.makedirs(os.path.dirname(cert), 0755)

        if not os.path.exists(os.path.dirname(key)):
            os.makedirs(os.path.dirname(key), 0755)

        if os.path.exists(cert) and os.path.exists(key):
            fetch_creds = False

        if force and self.conf.get_security_fetch_credential_from_relay():
            fetch_creds = True

        if fetch_creds:
            self.logger.debug("Fetching credentials from Globus")
            setup_key = None

            endpoint_name = self.conf.get_endpoint_name()
            setup_key = None

            if endpoint_name is not None:
                try:
                    (status_code, status_reason, data) = self.api.endpoint(
                            endpoint_name)
                    setup_key = data.get('globus_connect_setup_key')
                except:
                    pass

            if setup_key is None:
                # create dummy endpoint to get a setup_key
                dummy_endpoint_name = "gcmu-temp-" + str(uuid.uuid4())
                (status_code, status_reason, data) = self.api.endpoint_create(
                    endpoint_name = dummy_endpoint_name,
                    public = False, is_globus_connect = True)
                setup_key = data['globus_connect_setup_key']
                self.api.endpoint_delete(dummy_endpoint_name)

            fetcher = FetchCreds(debug=self.debug)

            cred = fetcher.get_cert_and_key(setup_key)
            if cred is not None:
                old_umask = os.umask(0133)
                cfp = open(cert, "w")
                try:
                    cfp.write(cred[0])
                finally:
                    cfp.close()
                os.umask(old_umask)

                old_umask = os.umask(0177)
                cfp = open(key, "w")
                try:
                    cfp.write(cred[1])
                finally:
                    cfp.close()
                os.umask(old_umask)

        certdir = self.conf.get_security_trusted_certificate_directory()
        if not os.path.exists(certdir):
            os.makedirs(certdir, 0755)
        security.install_ca(certdir)
        if not os.path.exists(self.conf.get_security_gridmap_file()):
            gridmap = file(self.conf.get_security_gridmap_file(), "w")
            if gridmap is not None:
                gridmap.close()

    def enable(self, service):
        service_enable = None

        if service_enable is None:
            systemctl_paths = ["/bin/systemctl", "/usr/bin/systemctl"]
            for systemctl in systemctl_paths:
                if os.path.exists(systemctl):
                    service_enable = [systemctl, "enable", service +".service"]
                    break

        if service_enable is None:
            update_rcd_paths = ["/sbin/update-rc.d", "/usr/sbin/update-rc.d"]
            for update_rcd in update_rcd_paths:
                if os.path.exists(update_rcd):
                    service_enable = [update_rcd, service, "enable"]
                    break

        if service_enable is None:
            chkconfig_paths = ["/sbin/chkconfig", "/usr/sbin/chkconfig"]
            for chkconfig in chkconfig_paths:
                if os.path.exists(chkconfig):
                    service_enable = [chkconfig, service, "on"]
                    break

        if service_enable is not None:
            enabler = Popen(service_enable, stdin=None,
                    stdout=PIPE, stderr=PIPE)
            (out, err) = enabler.communicate()
            if out is not None and out != "" and out != "\n":
                self.logger.info(out,)
            if err is not None and err != "" and err != "\n":
                self.logger.warn(err,)

    def restart(self, service):
        args = [
                os.path.join(
                    self.conf.root, "etc", "init.d",
                    service),
                "restart"]
        service_command = None
        starters = [
            "/sbin/service",
            "/usr/sbin/service",
            "/usr/sbin/invoke-rc.d"
        ]

        for path in starters:
            if os.path.exists(path):
                service_command = path
                break

        if service_command is not None:
            args = [service_command, service, "restart"]

        restarter = Popen(args, stdin = None, stdout=PIPE, stderr=PIPE)
        (out, err) = restarter.communicate()
        if out is not None and out != "" and out != "\n":
            self.logger.info(out,)
        if err is not None and err != "" and err != "\n":
            self.logger.warn(err,)

class SetupGridFtpService(SetupService):
    """
    Configure a GridFTP service based on a GCMU configuration. 
    """
    def __init__(self, **kwargs):
        super(SetupGridFtpService, self).__init__(**kwargs)

    def configure_security(self, force=False):
        """
        Set up the security environment for this GridFTP server, if it is
        local to this machine. We'll use a GC endpoint credential from the
        SetupService above if configured in the security section. If there
        is a remote MyProxy server defined in the configuration file, then
        we will fetch its CA credentials so that we can trust the certificates
        it issues
        """
        server = self.conf.get_gridftp_server()
        if self.is_local_gridftp():
            super(SetupGridFtpService, self).configure_security()

            myproxy_server = self.conf.get_myproxy_server()
            if myproxy_server is not None and not self.is_local_myproxy():
                print "Fetching MyProxy CA trust roots"
                cadir = self.conf.get_security_trusted_certificate_directory()

                if force and os.path.exists(cadir):
                    shutil.rmtree(cadir, ignore_errors=True)

                pipe_env = copy.copy(os.environ)
                # If we have valid credential, myproxy will try to use it, but,
                # if the server doesn't trust it there are some errors.
                #
                # We'll make that impossible by setting some environment
                # variables
                pipe_env['X509_CERT_DIR'] = cadir
                pipe_env['X509_USER_CERT'] = ""
                pipe_env['X509_USER_KEY'] = ""
                pipe_env['X509_USER_PROXY'] = ""
                if self.conf.get_myproxy_dn() is not None:
                    pipe_env['MYPROXY_SERVER_DN'] = self.conf.get_myproxy_dn()

                args = [ 'myproxy-get-trustroots', '-b', '-s',
                        self.conf.get_myproxy_server() ]
                myproxy_bootstrap = Popen(args, stdout=PIPE, stderr=PIPE, 
                    env=pipe_env)
                (out, err) = myproxy_bootstrap.communicate()
                returncode = myproxy_bootstrap.returncode

                if returncode != 0:
                    raise Exception("Error: %d\n%s\n%s" %(returncode, out, err))

    def configure_server(self, force=False):
        """
        For the GridFTP configuration, we'll create a file in /etc/gridftp.d
        that contains our configuration options. The default gridftp setup will
        parse that as well as anything else there, but provides a convenient
        place for the setup info to be
        """
        server = self.conf.get_gridftp_server()

        etc_gridftp_d = self.conf.get_etc_gridftp_d()
        var_gridftp_d = self.conf.get_var_gridftp_d()
        conf_file_name = os.path.join(
                var_gridftp_d, "globus-connect-multiuser")
        conf_link_name = os.path.join(
                etc_gridftp_d, "globus-connect-multiuser")

        if os.path.lexists(conf_link_name):
            os.remove(conf_link_name)

        if not self.is_local_gridftp():
            return

        if server is not None:
            self.logger.debug("Creating gridftp configuration")

            if not os.path.exists(etc_gridftp_d):
                os.makedirs(etc_gridftp_d, 0755)
            if not os.path.exists(var_gridftp_d):
                os.makedirs(var_gridftp_d, 0755)

            conf_file = file(conf_file_name, "w")
            try:
                version = pkgutil.get_data(
                    "globus.connect.multiuser.setup",
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
                        data_interface = self.conf.get_gridftp_server()
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
                cadir = \
                    self.conf.get_security_trusted_certificate_directory()
                if cadir is not None:
                    conf_file.write("$X509_CERT_DIR \"%s\"\n" \
                        % (cadir))
                cert = self.conf.get_security_certificate_file()
                if cert is not None:
                    conf_file.write("$X509_USER_CERT \"%s\"\n" \
                        % (cert))

                key = self.conf.get_security_key_file()
                if key is not None:
                    conf_file.write("$X509_USER_KEY \"%s\"\n" \
                        % (key))

                conf_file.write("$GRIDMAP %s\n" \
                        % (self.conf.get_security_gridmap_file()))
 
                rp = self.conf.get_gridftp_restrict_paths()
                if rp is not None:
                    conf_file.write("restrict_paths %s\n" % rp)

                os.symlink(conf_file_name, conf_link_name)
            finally:
                conf_file.close()

    def configure_sharing(self, force=False):
        self.logger.debug("Configuring GlobusOnline sharing for GridFTP server")

        etc_gridftp_d = self.conf.get_etc_gridftp_d()
        var_gridftp_d = self.conf.get_var_gridftp_d()

        conf_file_name = os.path.join(
                var_gridftp_d, "globus-connect-multiuser-sharing")
        conf_link_name = os.path.join(
                etc_gridftp_d, "globus-connect-multiuser-sharing")

        if os.path.lexists(conf_link_name):
            os.remove(conf_link_name)

        server = self.conf.get_gridftp_server()
        if not self.is_local_gridftp():
            return

        if not self.conf.get_gridftp_sharing_enabled():
            self.logger.debug("Disabling sharing")
            return

        if not os.path.exists(etc_gridftp_d):
            os.makedirs(etc_gridftp_d, 0755)
        if not os.path.exists(var_gridftp_d):
            os.makedirs(var_gridftp_d, 0755)

        if os.path.lexists(conf_link_name):
            os.remove(conf_link_name)

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

    def configure_authorization(self, force=False):
        method = self.conf.get_security_authorization_method()

        etc_gridftp_d = self.conf.get_etc_gridftp_d()
        var_gridftp_d = self.conf.get_var_gridftp_d()

        conf_file_name = os.path.join(var_gridftp_d,
                "globus-connect-multiuser-authorization")
        conf_link_name = os.path.join(etc_gridftp_d,
                "globus-connect-multiuser-authorization")
        server = self.conf.get_gridftp_server()

        if os.path.lexists(conf_link_name):
            os.remove(conf_link_name)

        if not self.is_local_gridftp():
            return

        if not os.path.exists(var_gridftp_d):
            os.makedirs(var_gridftp_d, 0755)
        if not os.path.exists(etc_gridftp_d):
            os.makedirs(etc_gridftp_d, 0755)

        if method == "MyProxyGridmapCallout":
            return self.configure_gridmap_verify_myproxy_callout(
                    conf_file_name, conf_link_name, force)
        elif method == "CILogon":
            return self.configure_cilogon(
                    conf_file_name, conf_link_name, force)

    def configure_gridmap_verify_myproxy_callout(self, conf_file_name, conf_link_name, force=False):
        self.logger.debug("Configuring myproxy callout for GridFTP")

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
                myproxy_ca_dn = security.get_certificate_subject(
                        self.conf.get_security_certificate_file())

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

    def configure_cilogon(self, conf_file_name, conf_link_name, force=False):
        self.logger.debug("Configuring CILogon authorization")

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

    def configure(self, force=False):
        server = self.conf.get_gridftp_server()
        if server is not None:
            self.logger.info("Configuring GridFTP Server")
            self.configure_security(force=force)
            self.configure_server(force=force)
            self.configure_authorization(force=force)
            self.configure_sharing(force=force)

    def unconfigure(self):
        gridftp_d = self.conf.get_etc_gridftp_d()
        for name in os.listdir(gridftp_d):
            if name.startswith("globus-connect") or name.startswith("gcmu"):
                os.remove(os.path.join(gridftp_d, name))

    def restart(self, force=False):
        SetupService.restart(self, "globus-gridftp-server")

    def enable(self):
        server = self.conf.get_gridftp_server()
        if server is not None and self.is_local_gridftp():
            SetupService.enable(self, "globus-gridftp-server")

class SetupMyProxyService(SetupService):
    """
    Configure a MyProxy service based on a GCMU configuration. 
    """
    def __init__(self, **kwargs):
        super(SetupMyProxyService, self).__init__(**kwargs)
        self.myproxy_cred_repo_config = None
        self.myproxy_ca_config = None
        self.myproxy_pam_config = None
        self.myproxy_mapapp_config = None

    def configure_myproxy_ca(self, force=False):
        if not self.conf.get_myproxy_ca():
            self.logger.debug("Not using MyProxy CA, nothing to configure")
            return

        cadir = self.conf.get_myproxy_ca_directory()
        if force:
            if cadir is not None and os.path.exists(cadir):
                shutil.rmtree(cadir, ignore_errors=True)

        if cadir is not None and not os.path.exists(cadir):
            ca_subject = self.conf.get_myproxy_ca_subject_dn()
            if ca_subject is None:
                ca_subject = security.get_certificate_subject(
                        self.conf.get_security_certificate_file(),
                        nameopt='RFC2253')
            try:
                args = [ 
                    'grid-ca-create',
                    '-nobuild',
                    '-verbose',
                    '-dir', self.conf.get_myproxy_ca_directory(),
                    '-subject', ca_subject,
                    '-noint']
                if force:
                    args.append('-force')
                ca_create = Popen(args, stdout = PIPE, stderr = PIPE)
                (out, err) = ca_create.communicate()
                self.logger.debug("ca create output: " + out)
                self.logger.debug("ca create stderr: " + err)
            finally:
                pass

            if ca_create.returncode != 0:
                raise Exception("Error creating CA: " + \
                    str(ca_create.returncode) + out + err)

        trustdir = self.conf.get_security_trusted_certificate_directory()
        if trustdir is not None:
            if not os.path.exists(trustdir):
                os.makedirs(trustdir, 0755)

            cert_path = os.path.join(cadir, "cacert.pem")
            signing_policy_path = os.path.join(cadir, "signing-policy")

            cahash = security.get_certificate_hash(cert_path)

            installed_cert_path = os.path.join(trustdir, cahash + ".0")
            installed_signing_policy = os.path.join(
                trustdir, cahash + ".signing_policy")

            shutil.copyfile(signing_policy_path, installed_signing_policy)
            os.chmod(installed_signing_policy, 0644)
            shutil.copyfile(cert_path, installed_cert_path)
            os.chmod(installed_cert_path, 0644)

        self.myproxy_ca_config = """
                certificate_issuer_cert "%(cadir)s/cacert.pem"
                certificate_issuer_key "%(cadir)s/private/cakey.pem"
                certificate_issuer_key_passphrase "%(passphrase)s"
                certificate_serialfile "%(cadir)s/serial"
                certificate_out_dir "%(cadir)s/newcerts"
                certificate_issuer_subca_certfile "%(cadir)s/cacert.pem"
                max_cert_lifetime 168
                cert_dir %(certdir)s
                """ % {
                    'cadir': cadir,
                    'passphrase': self.conf.get_myproxy_ca_passphrase(),
                    'certdir': \
                        self.conf.get_security_trusted_certificate_directory()
                }

    def configure_myproxy_pam(self, force=False):
        if not self.conf.get_myproxy_use_pam_login:
            self.myproxy_pam_config = None
            return

        self.myproxy_pam_config = """
                pam  "required"
                pam_id "login"
"""

    def configure_myproxy_mapapp(self, force=False):
        method = self.conf.get_security_authorization_method()
        if method != "MyProxyGridmapCallout":
            self.logger.debug("Not using MyProxy GridMap Callout, " +
                "nothing to configure")
            return
        cadir = self.conf.get_myproxy_ca_directory() 
        mapapp = os.path.join(cadir, 'mapapp')
        dn = security.get_certificate_subject(
                os.path.join(cadir, "cacert.pem"))

        mapapp_template = pkgutil.get_data(
                "globus.connect.multiuser", "mapapp-template")

        old_umask = os.umask(022)
        mapapp_file = file(mapapp, "w")
        try:
            mapapp_file.write(mapapp_template % { 'dn': dn })
        finally:
            mapapp_file.close()
        os.umask(old_umask)
        os.chmod(mapapp, 0755)

        self.myproxy_mapapp_config = "certificate_mapapp " + mapapp + "\n"

    def configure_myproxy_port(self, force=False):
        self.myproxy_port_config = ""
        server = self.conf.get_myproxy_server()
        if ":" in server:
            port = int(server.split(":")[1])
            self.myproxy_port_config = "-p %d " % port
        
    def configure_myproxy_cred_repo(self, force=False):
        self.myproxy_cred_repo_config = """
                authorized_retrievers      "*"
                default_retrievers         "*"
                authorized_renewers        "*"
                default_renewers           "none"
                default_key_retrievers     "none"
                trusted_retrievers         "*"
                default_trusted_retrievers "none"
                """

    def write_myproxy_conf(self):
        old_mask = os.umask(077)
        conffile = file(self.conf.get_myproxy_config_file(), "w")
        try:
            if self.myproxy_cred_repo_config is not None:
                conffile.write(self.myproxy_cred_repo_config)
            if self.myproxy_ca_config is not None:
                conffile.write(self.myproxy_ca_config)
            if self.myproxy_pam_config is not None:
                conffile.write(self.myproxy_pam_config)
            if self.myproxy_mapapp_config is not None:
                conffile.write(self.myproxy_mapapp_config)
        finally:
            conffile.close()
            os.umask(old_mask)

    def write_myproxy_init_conf(self):
        var_myproxy_d = self.conf.get_var_myproxy_d()
        etc_myproxy_d = self.conf.get_etc_myproxy_d()

        if not os.path.exists(var_myproxy_d):
            os.makedirs(var_myproxy_d, 0755)
        if not os.path.exists(etc_myproxy_d):
            os.makedirs(etc_myproxy_d, 0755)

        conf_file_name = os.path.join(var_myproxy_d, "globus-connect-multiuser")
        conf_link_name = os.path.join(etc_myproxy_d, "globus-connect-multiuser")

        if os.path.lexists(conf_link_name):
            os.remove(conf_link_name)

        conf_file = open(conf_file_name, 'w')
        try:
            store = os.path.join(
                self.conf.get_myproxy_ca_directory(),
                "store")

            if not os.path.exists(store):
                os.makedirs(store, 0700)
            if self.conf.get_myproxy_use_pam_login():
                conf_file.write("export MYPROXY_USER=root\n")
            conf_file.write("export X509_CERT_DIR=\"%s\"\n" % \
                    self.conf.get_security_trusted_certificate_directory())
            conf_file.write("export X509_USER_CERT=\"%s\"\n" % \
                    self.conf.get_security_certificate_file())
            conf_file.write("export X509_USER_KEY=\"%s\"\n" % \
                    self.conf.get_security_key_file())
            conf_file.write("export X509_USER_PROXY=\"\"\n")
            conf_file.write("export MYPROXY_OPTIONS=" + \
                    "\"${MYPROXY_OPTIONS:+$MYPROXY_OPTIONS }%s-c %s -s %s\"" \
                    % ( 
                        self.myproxy_port_config,
                        self.conf.get_myproxy_config_file(),
                        store))
            os.symlink(conf_file_name, conf_link_name)
        finally:
            conf_file.close()
        
    def configure(self, force=False):
        server = self.conf.get_myproxy_server()
        if not self.is_local_myproxy():
            self.logger.debug("MyProxy is not configured for this host")
            return

        self.logger.info("Configuring MyProxy Server")
        self.configure_security(force=force)
        self.configure_myproxy_ca(force=force)
        self.configure_myproxy_pam()
        self.configure_myproxy_mapapp()
        self.configure_myproxy_cred_repo()
        self.configure_myproxy_port()
        
        self.write_myproxy_conf()
        self.write_myproxy_init_conf()

    def unconfigure(self):
        server = self.conf.get_myproxy_server()
        if server is not None:
            if self.is_local_myproxy():
                myproxy_dir = self.conf.get_etc_myproxy_d()

                for name in os.listdir(myproxy_dir):
                    if name.startswith("globus-connect-multiuser"):
                        os.remove(os.path.join(myproxy_dir, name))

    def restart(self, force=False):
        server = self.conf.get_myproxy_server()
        if server is not None and self.is_local_myproxy():
            SetupService.restart(self, "myproxy-server")

    def enable(self):
        server = self.conf.get_myproxy_server()
        if server is not None and self.is_local_myproxy():
            SetupService.enable(self, "myproxy-server")

# vim: filetype=python:
