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

import gcmu.security
import gcmu.fetchcreds
import gcmu.setup

from globusonline.transfer.api_client import TransferAPIClient
from globusonline.transfer.api_client import TransferAPIError
from urlparse import urlparse

from subprocess import Popen, PIPE

class SetupService(gcmu.setup.Setup):
    def __init__(self, **kwargs):
        super(SetupService, self).__init__(**kwargs)

    def configure_security(self, force=False):
        fetch_creds = self.conf.get_security_fetch_credentials_from_relay()

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

        if force and self.conf.get_security_fetch_credentials_from_relay():
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

            fetcher = gcmu.fetchcreds.FetchCreds(debug=self.debug)

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

        self.logger.debug("Installing GlobusOnline Relay CA into GCMU trusted cert dir")

        certdir = self.conf.get_security_trusted_certificate_directory()
        if not os.path.exists(certdir):
            os.makedirs(certdir, 0755)
        gcmu.security.install_ca(certdir)

    def restart(self, service):
        (name, ver, id) = platform.linux_distribution()
        args = [
                os.path.join(
                    self.conf.root, self.conf.root, "etc", "init.d",
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
        restarter.communicate()

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
        if gcmu.is_local_service(self.conf.get_gridftp_server()):
            super(SetupGridFtpService, self).configure_security()

            if not gcmu.is_local_service(self.conf.get_myproxy_server()):
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
        For the GridFTP configuration, we'll create a file in /etc/gridftp.d that
        contains our configuration options. The default gridftp setup will
        parse that as well as anything else there, but provides a convenient
        place for the setup info to be
        """
        server = self.conf.get_gridftp_server()
        if server is not None:
            self.logger.debug("Creating gridftp configuration")
            gridftp_d = os.path.join("/", "etc", "gridftp.d")
            if not os.path.exists(gridftp_d):
                os.makedirs(gridftp_d, 0755)
            gridftp_gcmu_conf = file(os.path.join(gridftp_d, "gcmu"), "w")
            try:
                incoming_range = self.conf.get_gridftp_incoming_port_range()
                if incoming_range is not None:
                    gridftp_gcmu_conf.write(
                        "$GLOBUS_TCP_SOURCE_RANGE %d,%d\n" \
                        % (incoming_range[0], incoming_range[1]))
                outgoing_range = self.conf.get_gridftp_outgoing_port_range()
                if outgoing_range is not None:
                    gridftp_gcmu_conf.write("port_range %d,%d\n" \
                        % (outgoing_range[0], outgoing_range[1]))
                cadir = \
                    self.conf.get_security_trusted_certificate_directory()
                if cadir is not None:
                    gridftp_gcmu_conf.write("$X509_CERT_DIR \"%s\"\n" \
                        % (cadir))
                cert = self.conf.get_security_certificate_file()
                if cert is not None:
                    gridftp_gcmu_conf.write("$X509_USER_CERT \"%s\"\n" \
                        % (cert))

                key = self.conf.get_security_key_file()
                if key is not None:
                    gridftp_gcmu_conf.write("$X509_USER_KEY \"%s\"\n" \
                        % (key))

                gridftp_gcmu_conf.write("$GRIDMAP %s\n" \
                        % (self.conf.get_security_gridmap_file())
            finally:
                gridftp_gcmu_conf.close()

    def configure_sharing(self, force=False):
        self.logger.debug("Configuring GlobusOnline sharing for GridFTP server")

        gridftp_d = os.path.join(self.conf.root, "etc", "gridftp.d")
        gcmu_sharing = os.path.join(gridftp_d, "gcmu-sharing")

        if not self.conf.get_gridftp_sharing_enabled():
            if os.path.exists(gcmu_sharing):
                self.logger.debug("Disabling sharing")
                os.remove(gcmu_sharing)
            return

        if not os.path.exists(gridftp_d):
            os.makedirs(gridftp_d, 0755)

        gridftp_gcmu_conf = file(gcmu_sharing, "w")
        try:
            sharing_dn = self.conf.get_gridftp_sharing_dn()
	    gridftp_gcmu_conf.write("sharing_dn\t\"%s\"\n" % \
                sharing_dn)
            sharing_rp = self.conf.get_gridftp_sharing_restrict_port()
            if sharing_rp is not None:
                gridftp_gcmu_conf.write("sharing_rp %s" % sharing_rp)
            sharing_file = self.conf.get_gridftp_sharing_file()
            if sharing_file is not None:
                gridftp_gcmu_conf.write("sharing_file %s" % sharing_file)
        finally:
            gridftp_gcmu_conf.close()

    def configure_authorization(self, force=False):
        method = self.conf.get_security_authorization_method()

        if method == "MyProxyGridmapCallout":
            return self.configure_gridmap_verify_myproxy_callout(force)
        elif method == "Gridmap":
            return self.configure_gridmap(force)
        elif method == "CILogon":
            return self.configure_cilogon(force)

    def configure_gridmap_verify_myproxy_callout(self, force=False):
        self.logger.debug("Configuring myproxy callout for GridFTP")

        gridftp_d = os.path.join(self.conf.root, "etc", "gridftp.d")
        gcmu_authz = os.path.join(
                gridftp_d, "gcmu-authorization")

        if os.path.exists(gcmu_authz):
            self.logger.debug("Removing old authorization configuration")
            os.remove(gcmu_authz)

        if not os.path.exists(gridftp_d):
            os.makedirs(gridftp_d, 0755)

        gridftp_gcmu_conf = file(gcmu_authz, "w")
        try:
            gridftp_gcmu_conf.write("$GSI_AUTHZ_CONF \"%s\"\n" % (
                os.path.join(
                    self.conf.root, "etc",
                    "gridmap_verify_myproxy_callout-gsi_authz.conf"
                    )
                )
            )
            myproxy_certpath = None
            myproxy_signing_policy = None
            myproxy_dn = self.conf.get_myproxy_dn()

            if gcmu.is_local_service(self.conf.get_myproxy_server()):
                myproxy_certpath = os.path.join(
                    self.conf.get_myproxy_ca_directory(),
                    "cacert.pem")
                myproxy_signing_policy = os.path.join(
                    self.conf.get_myproxy_ca_directory(),
                    "signing-policy")
            elif myproxy_dn is not None:
                for certfile in os.listdir(cadir):
                    certpath = os.path.join(cadir, certfile)
                    if certfile[-2:] == '.0':
                        if gcmu.security.get_certificate_subject(
                                certpath) == myproxy_dn:
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

            myproxy_ca_hash = gcmu.security.get_certificate_hash(
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
            
            gridftp_gcmu_conf.write(
                    "$GLOBUS_MYPROXY_CA_CERT \"%s\"\n" %
                    installed_cert)
        finally:
            gridftp_gcmu_conf.close()

    def configure_gridmap(self, force=False):
        self.logger.debug("Configuring gridmap file for GridFTP")

        gridftp_d = os.path.join(self.conf.root, "etc", "gridftp.d")
        gcmu_authz = os.path.join(
                gridftp_d, "gcmu-authorization")

        if os.path.exists(gcmu_authz):
            self.logger.debug("Removing old authorization configuration")
            os.remove(gcmu_authz)

        if not os.path.exists(gridftp_d):
            os.makedirs(gridftp_d, 0755)

        gridftp_gcmu_conf = file(gcmu_authz, "w")
        try:
            gridmap = self.conf.get_security_gridmap_file()
            gridftp_gcmu_conf.write("$GRIDMAP \"%s\"\n" % (gridmap))
        finally:
            gridftp_gcmu_conf.close()

    def configure_cilogon(self, force=False):
        self.logger.debug("Configuring CILogon authorization")

        gridftp_d = os.path.join(self.conf.root, "etc", "gridftp.d")
        gcmu_authz = os.path.join(
                gridftp_d, "gcmu-authorization")

        if os.path.exists(gcmu_authz):
            self.logger.debug("Removing old authorization configuration")
            os.remove(gcmu_authz)

        if not os.path.exists(gridftp_d):
            os.makedirs(gridftp_d, 0755)

        gridftp_gcmu_conf = file(gcmu_authz, "w")
        try:
            cadir = self.conf.get_security_trusted_certificate_directory()
            ca = pkgutil.get_data("gcmu", "cilogon-basic.pem")
            signing_policy = pkgutil.get_data("gcmu",
                    "cilogon-basic.signing_policy")
            cahash = gcmu.security.get_certificate_hash_from_data(ca)

            idp = self.conf.get_security_cilogon_identity_provider()

            gcmu.security.install_ca(cadir, ca, signing_policy)

            gridftp_gcmu_conf.write(
                    "$GLOBUS_MYPROXY_CA_CERT \"%s\"\n" %
                    (os.path.join(cadir, cahash + ".0")))
            gridftp_gcmu_conf.write(
                    "$GLOBUS_MYPROXY_AUTHORIZED_DN " +
                    "\"/DC=org/DC=cilogon/C=US/O=%s\"\n" % (idp))
            gridftp_gcmu_conf.write(
                    "$GSI_AUTHZ_CONF \"%s\"\n" % (
                            os.path.join(
                            self.conf.root, "etc",
                            "gridmap_eppn_callout-gsi_authz.conf")))
        finally:
            gridftp_gcmu_conf.close()

    def configure(self, force=False):
        server = self.conf.get_gridftp_server()
        if server is not None:
            if gcmu.is_local_service(server):
                self.configure_security(force=force)
                self.configure_server(force=force)
                self.configure_authorization(force=force)
                self.configure_sharing(force=force)

    def unconfigure(self):
        server = self.conf.get_gridftp_server()
        if server is not None:
            if gcmu.is_local_service(server):
                gridftp_d = os.path.join(self.conf.root, "etc", "gridftp.d")
                for name in os.listdir(gridftp_d):
                    if name.startswith("gcmu"):
                        os.remove(os.path.join(gridftp_d, name))

    def restart(self, force=False):
        SetupService.restart(self, "globus-gridftp-server")

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
            old_umask = os.umask(0177)
            try:
                args = [ 
                    'grid-ca-create',
                    '-nobuild',
                    '-verbose',
                    '-dir', self.conf.get_myproxy_ca_directory(),
                    '-subject', gcmu.security.get_certificate_subject(
                            self.conf.get_security_certificate_file(),
                             nameopt="RFC2253"),
                    '-noint',
                    '-pass', self.conf.get_myproxy_ca_passphrase() ]
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

            cahash = gcmu.security.get_certificate_hash(cert_path)

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
        dn = gcmu.security.get_certificate_subject(
                os.path.join(cadir, "cacert.pem"))

        if force or not os.path.exists(mapapp):
            mapapp_template = pkgutil.get_data("gcmu", "mapapp-template")

            old_umask = os.umask(022)
            mapapp_file = file(mapapp, "w")
            #dn = "/".join(dn.split("/")[0:-1])
            try:
                mapapp_file.write(mapapp_template % { 'dn': dn })
            finally:
                mapapp_file.close()
            os.umask(old_umask)
            os.chmod(mapapp, 0755)

        self.myproxy_mapapp_config = "certificate_mapapp " + mapapp + "\n"

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

    def myproxy_server_init_conf(self):
        return os.path.join(self.conf.root, 'etc', 'gcmu',
                'myproxy-server-init.conf')

    def __write_myproxy_init_conf_hook(self):
        # Write myproxy-server init script configuration. First we add
        # our file hook and then we write the real configuration
        myproxy_server_conf = None
        lsb = None
        try:
            lsb = Popen(['lsb_release', '-is'], stdout=PIPE, stderr=PIPE)
            (out, err) = lsb.communicate()
            osname = out[0].strip()
            if osname in 'Debian|Ubuntu':
                myproxy_server_conf = os.path.join(
                    self.conf.root, 'etc', 'default', 'myproxy-server')
        finally:
            pass

        if myproxy_server_conf is None:
            myproxy_server_conf = os.path.join(
                        self.conf.root, 'etc', 'sysconfig', 'myproxy-server')
        
        myproxy_server_conf_fd = open(myproxy_server_conf, 'r+')
        try:
            conf_data = myproxy_server_conf_fd.read()
            if re.search("^# BEGIN GCMU CONFIG", conf_data, re.MULTILINE) \
                    is None:

                myproxy_server_conf_fd.write("""
# BEGIN GCMU CONFIG
if [ -r "%(myproxy_init_conf)s" ]; then
    . "%(myproxy_init_conf)s" 
fi
# END GCMU CONFIG
"""             % { 'myproxy_init_conf': self.myproxy_server_init_conf() })
        finally:
            myproxy_server_conf_fd.close()

    def write_myproxy_init_conf(self):
        self.__write_myproxy_init_conf_hook()

        confdir = os.path.dirname(self.myproxy_server_init_conf())
        if not os.path.exists(confdir):
            os.makedirs(confdir, 0755)

        init_conf = open(self.myproxy_server_init_conf(), 'w')
        try:
            store = os.path.join(
                self.conf.get_myproxy_ca_directory(),
                "store")

            if not os.path.exists(store):
                os.makedirs(store, 0700)

            if self.conf.get_myproxy_use_pam_login():
                init_conf.write("export MYPROXY_USER=root\n")
            init_conf.write("export X509_CERT_DIR=\"%s\"\n" % \
                    self.conf.get_security_trusted_certificate_directory())
            init_conf.write("export X509_USER_CERT=\"%s\"\n" % \
                    self.conf.get_security_certificate_file())
            init_conf.write("export X509_USER_KEY=\"%s\"\n" % \
                    self.conf.get_security_key_file())
            init_conf.write("export X509_USER_PROXY=\"\"\n")
            init_conf.write("export MYPROXY_OPTIONS=" + \
                    "\"${MYPROXY_OPTIONS:+$MYPROXY_OPTIONS }-c %s -s %s\"" \
                    % (
                        self.conf.get_myproxy_config_file(),
                        store))
        finally:
            init_conf.close()
        
    def configure(self, force=False):
        if not gcmu.is_local_service(self.conf.get_myproxy_server()):
            print "Service is running elsewhere, nothing to configure"
            return

        self.configure_security(force=force)
        self.configure_myproxy_ca(force=force)
        self.configure_myproxy_pam()
        self.configure_myproxy_mapapp()
        self.configure_myproxy_cred_repo()

        self.write_myproxy_conf()
        self.write_myproxy_init_conf()

    def unconfigure(self):
        server = self.conf.get_myproxy_server()
        if server is not None:
            if gcmu.is_local_service(server):
                gcmu_dir = os.path.join(self.conf.root, "etc", "gcmu")
                for name in os.listdir(gcmu_dir):
                    if name.startswith("myproxy"):
                        os.remove(os.path.join(gcmu_dir, name))

    def restart(self, force=False):
        SetupService.restart(self, "myproxy-server")

# vim: filetype=python:
