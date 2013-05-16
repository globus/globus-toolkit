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
import logging
import os
import getpass
import pkgutil
import platform
import re
import shutil
import socket
import ssl
import sys
import tempfile
import time
import urllib
import uuid

import globus.connect.security
import globusonline.transfer.api_client
import globusonline.transfer.api_client.verified_https
from globusonline.transfer.api_client import TransferAPIClient
from globusonline.transfer.api_client.goauth import get_access_token, GOCredentialsError
import globusonline.transfer.api_client.goauth

from globus.connect.security.fetchcreds import FetchCreds
from urlparse import urlparse
from subprocess import Popen, PIPE

__path__ = pkgutil.extend_path(__path__, __name__)

def to_unicode(data):
    """
    Coerce any type to unicode, assuming utf-8 encoding for strings.
    """
    if isinstance(data, unicode):
        return data
    if isinstance(data, str):
        return unicode(data, "utf-8")
    else:
        return unicode(data)

def is_ec2():
    url = 'http://169.254.169.254/latest/meta-data/'
    value = None
    try:
        socket.setdefaulttimeout(3.0)
        value = urllib.urlopen(url).read()
    except IOError:
        pass

    if value is not None and "404 - Not Found" in value:
        value = None

    return value is not None

def public_name():
    """
    Try to guess the public host name of this machine. If this is
    on a machine which is able to access ec2 metadata, it will use
    that; otherwise platform.node()
    """
    url = 'http://169.254.169.254/latest/meta-data/public-hostname'
    value = None
    try:
        socket.setdefaulttimeout(3.0)
        value = urllib.urlopen(url).read()
    except IOError:
        pass

    if value is not None and "404 - Not Found" in value:
        value = None

    if value is None:
        value = platform.node()
    return value

def public_ip():
    """
    Try to guess the public IP address of this machine. If this is
    on a machine which is able to access ec2 metadata, it will use
    that; otherwise it will return None
    """
    url = 'http://169.254.169.254/latest/meta-data/public-ipv4'

    value = None
    try:
        socket.setdefaulttimeout(3.0)
        value = urllib.urlopen(url).read()
    except IOError:
        pass

    if value is not None and "404 - Not Found" in value:
        value = None

    return value

def is_private_ip(name):
    """
    Determine if a host name resolves to an ip address in a private
    block.
    """
    if re.match("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", name):
        addr = name
    else:
        addr = socket.gethostbyname(name)
    octets = [int(x) for x in addr.split(".")]
    return (octets[0] == 10 or \
            (octets[0] == 172 and octets[1] >= 16 and octets[1] <= 31) or \
            (octets[0] == 192 and octets[1] == 168) or \
            (octets[0] == 127))

def is_local_service(name):
    """
    Determine if a service definition describes a service running on
    the local node. This is true if the service URL is for localhost,
    matches the machine's name, or ec2 public name
    """
    if name is None:
        return False
    if "://" in name:
        url = urlparse.urlparse(name)
        if ":" in url.netloc:
            name = url.netloc.split(":")[0]
        else:
            name = url.netloc
    elif ":" in name:
        name = name.split(":")[0]

    if name == "localhost":
        return True

    if '.' in name:
        name = name.split('.')[0]
    node = platform.node()
    if '.' in node:
        node = node.split('.')[0]

    if name == node:
        return True
    pn = public_name()
    if pn is not None and pn.split(".")[0] == name:
        return True
    return False

def get_api(conf):
    username = conf.get_go_username()
    if username is None:
        print "Globus Online Username: ",
        username = sys.stdin.readline().strip()
    password = conf.get_go_password()
    if password is None:
        password = getpass.getpass("Globus Online Password: ")

    auth_result = None

    go_instance = conf.get_go_instance()
    nexus_cert = None
    api_ca = None
    base_url = globusonline.transfer.api_client.DEFAULT_BASE_URL
    
    if go_instance == "Test":
        globusonline.transfer.api_client.goauth.HOST = \
                "graph.api.test.globuscs.info"
        nexus_cert = os.path.join(
                os.path.dirname(
                        globus.connect.security.__file__),
                        "graph.api.test.globuscs.info.pem")
        api_ca = os.path.join(
                os.path.dirname(
                        globus.connect.security.__file__),
                        "go-ca-cert.pem")
        globusonline.transfer.api_client.verified_https.match_hostname = \
                lambda cert, hostname: True
        base_url = "https://transfer.test.api.globusonline.org/" + globusonline.transfer.api_client.API_VERSION
        
    socket.setdefaulttimeout(300)

    for tries in xrange(1,10):
        try:
            auth_result = get_access_token(
                    username=username,
                    password=password,
                    ca_certs=nexus_cert)
            if auth_result is not None:
                break
        except ssl.SSLError, e:
            if "timed out" not in e.args[0]:
                raise e
            time.sleep(0.5)
        except GOCredentialsError, e:
            print "Globus Online Username: ",
            username = sys.stdin.readline().strip()
            password = getpass.getpass("Globus Online Password: ")

    api = TransferAPIClient(
            username=auth_result.username,
            goauth=auth_result.token,
            base_url=base_url,
            server_ca_file=api_ca)
    api.password = password
    return api

class GCMU(object):
    logger = logging.getLogger("globus.connect.multiuser.GCMU")
    handler = logging.StreamHandler()
    logger.addHandler(handler)

    def __init__(self, config_obj, api, debug=False, force=False, **kwargs):
        if config_obj is None:
            raise Exception("Invalid configuration object")
        if api is None:
            raise Exception("Invalid API object")

        self.logger = GCMU.logger
        if debug:
            GCMU.handler.setLevel(logging.DEBUG)
            GCMU.logger.setLevel(logging.DEBUG)
        else:
            GCMU.handler.setLevel(logging.INFO)
            GCMU.logger.setLevel(logging.INFO)
        self.conf = config_obj
        self.debug = debug
        self.force = force
        self.api = api
        self.service = None
        self.cilogon_cas = ['cilogon-basic', 'cilogon-silver']

        default_dir = os.path.join(self.conf.root, self.conf.DEFAULT_DIR)
        if not os.path.exists(default_dir):
            self.logger.debug("Creating directory: " + default_dir)
            os.makedirs(default_dir, 0755)

        self.errorcount = 0

    def is_local_gridftp(self):
        server = self.conf.get_gridftp_server()
        return server is not None and \
            (is_local_service(server) or \
                self.conf.get_gridftp_server_behind_nat())

    def is_local_myproxy(self):
        server = self.conf.get_myproxy_server()
        return server is not None and \
            (is_local_service(server) or \
                self.conf.get_myproxy_server_behind_nat())

    def is_local_oauth(self):
        server = self.conf.get_oauth_server()
        return server is not None and \
            (is_local_service(server) or \
                self.conf.get_oauth_server_behind_nat())

    def configure_credential(self, **kwargs):
        """
        Sets up a service's certificate and private key.

        If configured to use a relay credential, fetch one if there aren't
        already certificate and key files and put them into place. The
        kwarg force=True will force this function to ignore existing key and
        cert files and fetch new ones.

        If not configured to use a relay credential, check whether the
        certificate and key files exist. Warn if they are missing.
        """
        self.logger.debug("ENTER: GCMU.configure_credential()")
        cert = self.conf.get_security_certificate_file()
        key = self.conf.get_security_key_file()

        if self.conf.get_security_fetch_credential_from_relay():
            if kwargs.get('force') or \
                    (not os.path.exists(cert)) or (not os.path.exists(key)):
                if os.path.exists(cert):
                    self.logger.debug("Removing old certificate file")
                    os.remove(cert)
                if os.path.exists(key):
                    self.logger.debug("Removing old key file")
                    os.remove(key)

            if (not os.path.exists(cert)) or (not os.path.exists(key)):
                self.logger.debug("Fetching credential from relay")
                # create dummy endpoint to get a setup_key
                dummy_endpoint_name = "gcmu-temp-" + str(uuid.uuid4())
                (status_code, status_reason, data) = self.api.endpoint_create(
                    endpoint_name = dummy_endpoint_name,
                    public = False, is_globus_connect = True)
                setup_key = data['globus_connect_setup_key']
                self.api.endpoint_delete(dummy_endpoint_name)

                relay = "relay.globusonline.org"
                if self.conf.get_go_instance() == "Test":
                    relay = "cli.test.globusonline.org"

                self.logger.debug("Fetching key from relay " + relay)
                fetcher = FetchCreds(debug=self.debug, server=relay)

                (cert_data, key_data) = fetcher.get_cert_and_key(setup_key)


                for dirname in [os.path.dirname(cert), os.path.dirname(key)]: 
                    if not os.path.exists(dirname):
                        os.makedirs(dirname, 0755)

                old_umask = os.umask(0133)
                cfp = open(cert, "w")
                try:
                    self.logger.debug("Writing certificate to disk")
                    cfp.write(cert_data)
                finally:
                    cfp.close()
                os.umask(old_umask)

                old_umask = os.umask(0177)
                cfp = open(key, "w")
                try:
                    self.logger.debug("Writing key to disk")
                    cfp.write(key_data)
                finally:
                    cfp.close()
                os.umask(old_umask)
        else:
            if not os.path.exists(cert):
                self.logger.warning("Certificate file %s does not exist" 
                    % (cert))
            if not os.path.exists(key):
                self.logger.warning("Key file %s does not exist" % (key))

        self.logger.debug("EXIT: GCMU.configure_credential()")
        return (cert, key)

    def configure_trust_roots(self, **kwargs):
        """
        Configure the certificate trust roots for services. The different
        certificates that may be put into place are:
        - Globus Connect Relay CA
        - MyProxy CA
        - CILogon CA

        Also, if the CILogon CA is added to the trust roots, a cronjob
        will be registered to fetch the CRL associated with that CA
        periodically
        """
        self.logger.debug("ENTER: GCMU.configure_trust_roots()")
        certdir = self.conf.get_security_trusted_certificate_directory()
        if not os.path.exists(certdir):
            os.makedirs(certdir, 0755)

        # Install Globus Connect Relay CA
        relay_cert = pkgutil.get_data(
                "globus.connect.security",
                "go-ca-cert.pem")
        relay_signing_policy = pkgutil.get_data(
                "globus.connect.security",
                "go-ca-cert.signing_policy")
        globus.connect.security.install_ca(
                certdir,
                relay_cert,
                relay_signing_policy)
        # Install New Globus Online CA and intermediate CA signing policy
        # if sharing is enabled
        if self.conf.get_gridftp_sharing():
            go_transfer_ca_2_cert = pkgutil.get_data(
                    "globus.connect.security",
                    "go_transfer_ca_2.pem")
            go_transfer_ca_2_signing_policy = pkgutil.get_data(
                    "globus.connect.security",
                    "go_transfer_ca_2.signing_policy")
            globus.connect.security.install_ca(
                    certdir,
                    go_transfer_ca_2_cert,
                    go_transfer_ca_2_signing_policy)
            intermediate_hashes = ['14396025', 'c7ab88a4']
            go_transfer_ca_2_int_signing_policy = pkgutil.get_data(
                    "globus.connect.security",
                    "go_transfer_ca_2_int.signing_policy")
            globus.connect.security.install_signing_policy(
                    go_transfer_ca_2_int_signing_policy,
                    certdir,
                    intermediate_hashes[globus.connect.security.openssl_version()])

        # Install MyProxy CA
        myproxy_server = self.conf.get_myproxy_server()
        if myproxy_server is not None and self.is_local_myproxy():
            # Local myproxy server, just copy the files into location
            if self.conf.get_myproxy_ca():
                myproxy_ca_dir = self.conf.get_myproxy_ca_directory()
                myproxy_ca_cert = os.path.join(myproxy_ca_dir, "cacert.pem")
                myproxy_ca_signing_policy = os.path.join(
                        myproxy_ca_dir,
                        "signing-policy")
                globus.connect.security.install_ca(
                    certdir,
                    myproxy_ca_cert,
                    myproxy_ca_signing_policy)
        elif myproxy_server is not None:
            # Remote myproxy server, fetch trust roots from the service
            self.logger.debug("Fetching MyProxy CA trust roots")
            pipe_env = copy.deepcopy(os.environ)
            # If we have valid credential, myproxy will try to use it, but,
            # if the server doesn't trust it there are some errors.
            #
            # We'll make that impossible by setting some environment
            # variables
            pipe_env['X509_CERT_DIR'] = certdir
            pipe_env['X509_USER_CERT'] = ""
            pipe_env['X509_USER_KEY'] = ""
            pipe_env['X509_USER_PROXY'] = ""
            if self.conf.get_myproxy_dn() is not None:
                pipe_env['MYPROXY_SERVER_DN'] = self.conf.get_myproxy_dn()
            else:
                pipe_env['MYPROXY_SERVER_DN'] = \
                        self.get_myproxy_dn_from_server()

            self.logger.debug("fetching trust roots from myproxy server at " + self.conf.get_myproxy_server())
            self.logger.debug("expecting dn " + pipe_env['MYPROXY_SERVER_DN'])
            self.logger.debug("expecting to put them in " + certdir)
            args = [ 'myproxy-get-trustroots', '-b', '-s',
                    self.conf.get_myproxy_server() ]
            myproxy_bootstrap = Popen(args, stdout=PIPE, stderr=PIPE, 
                env=pipe_env)
            (out, err) = myproxy_bootstrap.communicate()
            if out is not None:
                self.logger.debug(out)
            if err is not None:
                self.logger.warn(err)
            if myproxy_bootstrap.returncode != 0:
                self.logger.debug("myproxy bootstrap returned " + str(myproxy_bootstrap.returncode))


        # Install CILogon CAs
        if self.conf.get_security_identity_method() == "CILogon":
            for cilogon_ca in self.cilogon_cas:
                cilogon_cert = pkgutil.get_data(
                        "globus.connect.security",
                        cilogon_ca + ".pem")
                cilogon_signing_policy = pkgutil.get_data(
                        "globus.connect.security",
                        cilogon_ca + ".signing_policy")

                globus.connect.security.install_ca(
                    certdir,
                    cilogon_cert,
                    cilogon_signing_policy)

                # Install CILogon update CRL cron job
                cilogon_hash = globus.connect.security.\
                        get_certificate_hash_from_data(cilogon_cert)

                cilogon_crl_script = pkgutil.get_data(
                        "globus.connect.security",
                        "cilogon-crl-fetch")

                cilogon_crl_cron_path = os.path.join(self.conf.root,
                        "etc/cron.hourly",
                        "globus-connect-multiuser-" + cilogon_ca + "-crl")

                cilogon_crl_cron_file = file(cilogon_crl_cron_path, "w")
                try:
                    cilogon_crl_cron_file.write(cilogon_crl_script % {
                        'certdir': certdir,
                        'cilogon_url': 'http://crl.cilogon.org/' + \
                            cilogon_ca + '.crl',
                        'cilogon_hash': cilogon_hash
                    })
                    os.chmod(cilogon_crl_cron_path, 0755)
                finally:
                    cilogon_crl_cron_file.close()
        self.logger.debug("EXIT: GCMU.configure_trust_roots()")

    def cleanup_trust_roots(self, **kwargs):
        """
        Clean up the certificate trust roots for services. The different
        certificates that may be cleaned up are:
        - Globus Connect Relay CA
        - MyProxy CA
        - CILogon CA

        Also, if the CILogon CA is in the trust roots, remove the CRL
        fetch cronjobs
        """
        self.logger.debug("ENTER: GCMU.cleanup_trust_roots()")
        certdir = self.conf.get_security_trusted_certificate_directory()
        if not os.path.exists(certdir):
            return

        hashes = []
        # Remove Globus Connect Relay CA
        relay_cert = pkgutil.get_data(
                "globus.connect.security",
                "go-ca-cert.pem")

        hashes.append(globus.connect.security.get_certificate_hash_from_data(
                relay_cert))

        # Install New Globus Online CA and intermediate CA signing policy
        # if sharing is enabled
        if self.conf.get_gridftp_sharing():
            go_transfer_ca_2_cert = pkgutil.get_data(
                    "globus.connect.security",
                    "go_transfer_ca_2.pem")
            hashes.append(
                    globus.connect.security.get_certificate_hash_from_data(
                            go_transfer_ca_2_cert))
            intermediate_hashes = ['14396025', 'c7ab88a4']
            hashes.append(
                    intermediate_hashes[globus.connect.security.openssl_version()])

        # CILogon CAs
        if self.conf.get_security_identity_method() == "CILogon":
            for cilogon_ca in self.cilogon_cas:
                cilogon_cert = pkgutil.get_data(
                        "globus.connect.security",
                        cilogon_ca + ".pem")
                hashes.append(
                        globus.connect.security.get_certificate_hash_from_data(
                                cilogon_cert))
        else: # MyProxy CA
            myproxy_server = self.conf.get_myproxy_server()
            if myproxy_server is not None and self.is_local_myproxy():
                # Local myproxy server, just copy the files into location
                if self.conf.get_myproxy_ca():
                    myproxy_ca_dir = self.conf.get_myproxy_ca_directory()
                    myproxy_ca_cert = os.path.join(myproxy_ca_dir, "cacert.pem")
                    hashes.append(
                            globus.connect.security.get_certificate_hash(
                                    myproxy_ca_cert))
            elif myproxy_server is not None:
                # Ugly hack to get what we might have downloaded during install
                # time
                temppath = tempfile.mkdtemp()
                pipe_env['X509_CERT_DIR'] = temppath
                pipe_env['X509_USER_CERT'] = ""
                pipe_env['X509_USER_KEY'] = ""
                pipe_env['X509_USER_PROXY'] = ""
                if self.conf.get_myproxy_dn() is not None:
                    pipe_env['MYPROXY_SERVER_DN'] = self.conf.get_myproxy_dn()
                else:
                    pipe_env['MYPROXY_SERVER_DN'] = \
                            self.get_myproxy_dn_from_server()
                args = [ 'myproxy-get-trustroots', '-b', '-s',
                        self.conf.get_myproxy_server() ]
                myproxy_bootstrap = Popen(args, stdout=PIPE, stderr=PIPE, 
                    env=pipe_env)
                (out, err) = myproxy_bootstrap.communicate()
                if out is not None:
                    self.logger.debug(out)
                if err is not None:
                    self.logger.warn(err)
                if myproxy_bootstrap.returncode != 0:
                    self.logger.debug("myproxy bootstrap returned " +
                            str(myproxy_bootstrap.returncode))
                for entry in os.listdir(temppath):
                    if entry.endswith(".0"):
                        hashes.append(entry.split(".",1)[0])
                shutil.rmtree(temppath, ignore_errors=True)

        for ca_hash in hashes:
            ca_file = os.path.join(certdir, ca_hash+".0")
            signing_policy_file = os.path.join(
                    certdir,
                    ca_hash+".signing_policy")
            crl_file =  os.path.join(
                    certdir,
                    ca_hash+".r0")
            if os.path.exists(ca_file):
                os.remove(ca_file)
            if os.path.exists(signing_policy_file):
                os.remove(signing_policy_file)
            if os.path.exists(crl_file):
                os.remove(crl_file)

        # CRL Fetch cronjobs
        crondir = os.path.join(self.conf.root, "etc/cron.hourly")
        for cronjob in os.listdir(crondir):
            if cronjob.startswith("globus-connect-multiuser"):
                cronfile = os.path.join(crondir, cronjob)
                if os.path.exists(cronfile):
                    os.remove(cronfile)
        self.logger.debug("EXIT: GCMU.cleanup_trust_roots()")

    def get_myproxy_dn_from_server(self):
        self.logger.debug("ENTER: get_myproxy_dn_from_server()")
        
        server_dn = None
        self.logger.debug("fetching myproxy dn from server")
        temppath = tempfile.mkdtemp()

        pipe_env = copy.deepcopy(os.environ)
        # If we have valid credential, myproxy will try to use it, but,
        # if the server doesn't trust it there are some errors.
        #
        # We'll make that impossible by setting some environment
        # variables
        pipe_env['X509_CERT_DIR'] = temppath
        pipe_env['X509_USER_CERT'] = ""
        pipe_env['X509_USER_KEY'] = ""
        pipe_env['X509_USER_PROXY'] = ""

        args = [ 'myproxy-get-trustroots', '-b', '-s',
                self.conf.get_myproxy_server() ]
        myproxy_bootstrap = Popen(args, stdout=PIPE, stderr=PIPE, 
            env=pipe_env)
        (out, err) = myproxy_bootstrap.communicate()
        server_dn_match = re.search("MYPROXY_SERVER_DN=\"([^\"]*)\"", err)
        if server_dn_match is not None:
            server_dn = server_dn_match.groups()[0]

        shutil.rmtree(temppath, ignore_errors=True)
        self.logger.debug("MyProxy DN is " + str(server_dn))
        self.logger.debug("EXIT: get_myproxy_dn_from_server()")

        return server_dn

    def disable(self, **kwargs):
        service_disable = None

        if service_disable is None:
            systemctl_paths = ["/bin/systemctl", "/usr/bin/systemctl"]
            for systemctl in systemctl_paths:
                if os.path.exists(systemctl):
                    service_disable = [systemctl, "--quiet", "disable",
                            self.service + ".service"]
                    break

        if service_disable is None:
            update_rcd_paths = ["/sbin/update-rc.d", "/usr/sbin/update-rc.d"]
            for update_rcd in update_rcd_paths:
                if os.path.exists(update_rcd):
                    service_disable = [update_rcd, self.service, "disable"]
                    break

        if service_disable is None:
            chkconfig_paths = ["/sbin/chkconfig", "/usr/sbin/chkconfig"]
            for chkconfig in chkconfig_paths:
                if os.path.exists(chkconfig):
                    service_disable = [chkconfig, self.service, "off"]
                    break

        if service_disable is not None:
            disabler = Popen(service_disable, stdin=None,
                    stdout=PIPE, stderr=PIPE)
            (out, err) = disabler.communicate()
            if out is not None and out != "" and out != "\n":
                self.logger.info(out,)
            if err is not None and err != "" and err != "\n":
                self.logger.warn(err,)

    def enable(self, **kwargs):
        service_enable = None

        if service_enable is None:
            systemctl_paths = ["/bin/systemctl", "/usr/bin/systemctl"]
            for systemctl in systemctl_paths:
                if os.path.exists(systemctl):
                    service_enable = [systemctl, "--quiet", "enable",
                            self.service + ".service"]
                    break

        if service_enable is None:
            update_rcd_paths = ["/sbin/update-rc.d", "/usr/sbin/update-rc.d"]
            for update_rcd in update_rcd_paths:
                if os.path.exists(update_rcd):
                    service_enable = [update_rcd, self.service, "enable"]
                    break

        if service_enable is None:
            chkconfig_paths = ["/sbin/chkconfig", "/usr/sbin/chkconfig"]
            for chkconfig in chkconfig_paths:
                if os.path.exists(chkconfig):
                    service_enable = [chkconfig, self.service, "on"]
                    break

        if service_enable is not None:
            enabler = Popen(service_enable, stdin=None,
                    stdout=PIPE, stderr=PIPE)
            (out, err) = enabler.communicate()
            if out is not None and out != "" and out != "\n":
                self.logger.info(out,)
            if err is not None and err != "" and err != "\n":
                self.logger.warn(err,)

    def stop(self, **kwargs):
        (name, ver, id) = platform.linux_distribution()
        args = ["/etc/init.d/" + self.service, "stop"]

        if name == 'CentOS' \
                or name == 'RedHat' \
                or name.startswith("Scientific") \
                or name == 'Fedora':
            args = ["/sbin/service", self.service, "stop"]
        elif name == 'Ubuntu' or name == 'Debian':
            args = ["/usr/sbin/service", self.service, "stop"]

        restarter = Popen(args, stdin = None, stdout=PIPE, stderr=PIPE)
        restarter.communicate()
                    

    def restart(self, **kwargs):
        self.logger.debug("ENTER: GCMU.restart()")
        (name, ver, id) = platform.linux_distribution()
        args = ["/etc/init.d/" + self.service, "restart"]

        if name == 'CentOS' \
                or name == 'RedHat' \
                or name.startswith("Scientific") \
                or name == 'Fedora':
            args = ["/sbin/service", self.service, "restart"]
        elif name == 'Ubuntu' or name == 'Debian':
            args = ["/usr/sbin/service", self.service, "restart"]

        self.logger.debug("restarting with " + " ".join(args))
        restarter = Popen(args, stdin = None, stdout=PIPE, stderr=PIPE)
        restarter.communicate()
        self.logger.debug("EXIT: GCMU.restart()")
                    
# vim: filetype=python: nospell:
