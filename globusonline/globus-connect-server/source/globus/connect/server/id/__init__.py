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
"""
Configure a MyProxy server for use with Globus

"""

import copy
import logging
import os
import pkgutil
import string
import shutil
import sys

__path__ = pkgutil.extend_path(__path__, __name__)

import globus.connect.security as security
import globus.connect.server as gcmu

from globusonline.transfer.api_client import TransferAPIClient
from globusonline.transfer.api_client import TransferAPIError
from urlparse import urlparse

from subprocess import Popen, PIPE

class ID(gcmu.GCMU):
    """
    Configure a MyProxy service based on a GCMU configuration. 
    """
    def __init__(self, **kwargs):
        super(ID, self).__init__(**kwargs)
        self.myproxy_cred_repo_config = None
        self.myproxy_ca_config = None
        self.myproxy_pam_config = None
        self.myproxy_mapapp_config = None
        self.service = "myproxy-server"

    def is_local(self):
        return self.is_local_myproxy()

    def setup(self, **kwargs):
        self.logger.debug("ENTER: ID.setup()")

        if not self.is_local_myproxy():
            print "Using MyProxy server on " \
                + str(self.conf.get_myproxy_server())
            self.logger.debug("No MyProxy configured for this host")
            return

        self.configure_credential(**kwargs)
        self.configure_myproxy_ca(**kwargs)
        self.configure_trust_roots(**kwargs)
        self.configure_myproxy_pam()
        self.configure_myproxy_mapapp()
        self.configure_myproxy_cred_repo()
        self.configure_myproxy_port()
        
        self.write_myproxy_conf()
        self.write_myproxy_init_conf()
        self.enable()
        self.restart()
        cadir = self.conf.get_myproxy_ca_directory()
        cert_path = os.path.join(cadir, "cacert.pem")

        print "Configured MyProxy server on " \
            + self.conf.get_myproxy_server() + ":7512"
        print "CA DN: " + security.get_certificate_subject(cert_path)
        myproxy_dn = self.get_myproxy_dn_from_server()
        if myproxy_dn is not None:
            print "Service DN: " + myproxy_dn

        self.logger.debug("EXIT: ID.setup()")
        
    def cleanup(self, **kwargs):
        self.logger.debug("ENTER: IO:cleanup()")
        server = self.conf.get_myproxy_server()
        if server is None:
            self.logger.debug("No MyProxy server defined")
            return

        self.disable()
        self.stop()

        myproxy_dir = self.conf.get_etc_myproxy_d()

        if os.path.exists(myproxy_dir):
            for name in os.listdir(myproxy_dir):
                if name.startswith("globus-connect-server"):
                    os.remove(os.path.join(myproxy_dir, name))
        self.cleanup_trust_roots()
        self.logger.debug("EXIT: IO:cleanup()")


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
                out = "".join(s for s in out if s in string.printable)
                err = "".join(s for s in err if s in string.printable)
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
                "globus.connect.server", "mapapp-template")

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

        conf_file_name = os.path.join(var_myproxy_d, "globus-connect-server")
        conf_link_name = os.path.join(etc_myproxy_d, "globus-connect-server")

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

# vim: filetype=python:
