# Copyright 2013 University of Chicago
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
import gcmu
import os
import ConfigParser

class ConfigFile(ConfigParser.ConfigParser):
    GLOBUSONLINE_SECTION = "GlobusOnline"
    ENDPOINT_SECTION = "Endpoint"
    SECURITY_SECTION = "Security"
    GRIDFTP_SECTION = "GridFTP"
    MYPROXY_SECTION = "MyProxy"

    USER_OPTION = "User"
    PASSWORD_OPTION = "Password"
    DATA_DIRECTORY_OPTION = "DataDirectory"
    NAME_OPTION = "Name"
    PUBLIC_OPTION = "Public"
    DEFAULT_DIRECTORY_OPTION = "DefaultDirectory"
    FETCH_CREDENTIAL_FROM_RELAY_OPTION = "FetchCredentialFromRelay"
    CERTIFICATE_FILE_OPTION = "CertificateFile"
    KEY_FILE_OPTION = "KeyFile"
    TRUSTED_CERTIFICATE_DIRECTORY_OPTION = "TrustedCertificateDirectory"
    USE_MYPROXY_GRIDMAP_CALLOUT_OPTION = "UseMyProxyGridmapCallout"
    
    SERVER_OPTION = "Server"
    ENDPOINTS_OPTION = "Endpoints"
    INCOMING_PORT_RANGE_OPTION = "IncomingPortRange"
    OUTGOING_PORT_RANGE_OPTION= "OutgoingPortRange"
    DATA_INTERFACE_OPTION = "DataInterface"
    RESTRICT_PATHS_OPTION = "RestrictPaths"
    SHARING_ENABLED_OPTION = "SharingEnabled"
    SHARING_DN = "SharingDN"
    SHARING_RESTRICT_PORT = "SharingRestrictPaths"
    SHARING_FILE = "SharingFile"
    SHARING_FILE_CONTROL = "SharingFileControl"
    DEFAULT_SHARING_DN = "/C=US/O=Globus Consortium/OU=Globus Connect User" + \
        "/CN=__transfer__"
    DN_OPTION = "DN"
    CA_OPTION = "CA"
    CA_DIRECTORY_OPTION = "CaDirectory"
    CA_PASSPHRASE_OPTION = "CaPassphrase"
    USE_PAM_LOGIN_OPTION = "UsePamLogin"
    CONFIG_FILE_OPTION = "ConfigFile"

    def __init__(self, root="/", config_file=None):
        defaults = copy.copy(os.environ)
        if "HOSTNAME" not in defaults:
            defaults["HOSTNAME"] = gcmu.public_name()
        if "SHORT_HOSTNAME" not in defaults:
            defaults["SHORT_HOSTNAME"] = defaults["HOSTNAME"].split(".")[0]
        if "GO_USER" not in defaults:
            defaults["GO_USER"] = ""
        if "GO_PASSWORD" not in defaults:
            defaults["GO_PASSWORD"] = ""

        ConfigParser.ConfigParser.__init__(self, defaults)
        self.root = root
        if config_file is None:
            config_file = os.path.join(self.root, "etc", "gcmu.conf")
        self.read(config_file)

    def __get_list(self, section, option, maxsplit = 0):
        if not self.has_option(section, option):
            return []
        optstr = self.get(section, option).strip()
        if optstr == '':
            return []
        if maxsplit > 0:
            return [x.strip() for x in optstr.split(',', maxsplit)]
        else:
            return [x.strip() for x in optstr.split(',')]

    def get_go_username(self):
        user = None
        if self.has_option(
                ConfigFile.GLOBUSONLINE_SECTION,
                ConfigFile.USER_OPTION):
            user = self.get(
                ConfigFile.GLOBUSONLINE_SECTION,
                ConfigFile.USER_OPTION)
        if user == '':
            user = None
        return user

    def get_go_password(self):
        password = None
        if self.has_option(
                ConfigFile.GLOBUSONLINE_SECTION,
                ConfigFile.PASSWORD_OPTION):
            password = self.get(
                ConfigFile.GLOBUSONLINE_SECTION,
                ConfigFile.PASSWORD_OPTION)
        if password == '':
            password = None
        return password

    def get_endpoint_name(self):
        name = None
        if self.has_option(
                ConfigFile.ENDPOINT_SECTION,
                ConfigFile.NAME_OPTION):
            name = self.get(
                ConfigFile.ENDPOINT_SECTION,
                ConfigFile.NAME_OPTION)
        if name == '':
            name = gcmu.public_name()
        return name

    def get_endpoint_public(self):
        public = False
        if self.has_option(
                ConfigFile.ENDPOINT_SECTION,
                ConfigFile.PUBLIC_OPTION):
            public = self.getboolean(
                ConfigFile.ENDPOINT_SECTION,
                ConfigFile.PUBLIC_OPTION)
        return public

    def get_endpoint_default_dir(self):
        default_dir = None
        if self.has_option(
                ConfigFile.ENDPOINT_SECTION,
                ConfigFile.DEFAULT_DIRECTORY_OPTION):
            default_dir = self.get(
                ConfigFile.ENDPOINT_SECTION,
                ConfigFile.DEFAULT_DIRECTORY_OPTION)
        if default_dir == '' or default_dir is None:
            default_dir = '/~/'
        return default_dir

    def get_security_fetch_credentials_from_relay(self):
        fetch_credentials_from_relay = True
        if self.has_option(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.FETCH_CREDENTIAL_FROM_RELAY_OPTION):
            fetch_credentials_from_relay = self.getboolean(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.FETCH_CREDENTIAL_FROM_RELAY_OPTION)
        return fetch_credentials_from_relay

    def get_security_certificate_file(self):
        certificate = None
        if self.has_option(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.CERTIFICATE_FILE_OPTION):
            certificate = self.get(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.CERTIFICATE_FILE_OPTION)
        if certificate == '':
            certificate = None
        if certificate is None:
            certificate = os.path.join(
                self.root, 'etc', 'gcmu', 'grid-security', 'hostcert.pem')
        else:
            certificate = os.path.abspath(certificate)

        return certificate

    def get_security_key_file(self):
        key = None
        if self.has_option(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.KEY_FILE_OPTION):
            key = self.get(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.KEY_FILE_OPTION)
        if key == '':
            key = None
        if key is None:
            key = os.path.join(self.root, 'etc', 'gcmu', 'grid-security',
                'hostkey.pem')
        else:
            key = os.path.abspath(key)
        return key

    def get_security_trusted_certificate_directory(self):
        cadir = None
        if self.has_option(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.TRUSTED_CERTIFICATE_DIRECTORY_OPTION):
            cadir = self.get(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.TRUSTED_CERTIFICATE_DIRECTORY_OPTION)
        if cadir == '':
            cadir = None
        if cadir is None:
            cadir = os.path.join(self.root, 'etc', 'gcmu', 'grid-security', 'certificates')
        return os.path.abspath(cadir)

    def get_security_use_myproxy_gridmap_callout(self):
        use_gridmap_callout = True
        if self.has_option(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.USE_MYPROXY_GRIDMAP_CALLOUT_OPTION):
            use_gridmap_callout = self.getboolean(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.USE_MYPROXY_GRIDMAP_CALLOUT_OPTION)
        return use_gridmap_callout

    def get_gridftp_server(self):
        server = None
        if self.has_option(
                ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SERVER_OPTION):
            server = self.get(
                ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SERVER_OPTION)
        if server == '':
            server = None
        elif server is not None:
            name = None
            if "://" in server:
                url = urlparse.urlparse(server)
                if ":" in url.netloc:
                    name = url.netloc.split(":")[0]
                else:
                    name = url.netloc
            elif ":" in server:
                name = server.split(":")[0]
            if name == "localhost":
                server = gcmu.public_hostname()

        return server

    def get_gridftp_dn(self):
        dn = None
        if self.has_option(
                ConfigFile.GRIDFTP_SECTION,
                ConfigFile.DN_OPTION):
            dn = self.get(
                ConfigFile.GRIDFTP_SECTION,
                ConfigFile.DN_OPTION)
        if dn == '':
            dn = None
        return dn

    def get_gridftp_endpoints(self):
        return self.__get_list(
                ConfigFile.GRIDFTP_SECTION,
                ConfigFile.ENDPOINTS_OPTION)

    def get_gridftp_incoming_port_range(self):
        incoming_port_range = [
            int(x) for x in self.__get_list(
                ConfigFile.GRIDFTP_SECTION,
                ConfigFile.INCOMING_PORT_RANGE_OPTION,
                1)]
        if len(incoming_port_range) == 0:
            return None
        if len(incoming_port_range) != 2:
            raise Exception("Invalid port range %s" % (
                    str(incoming_port_range)))
        return incoming_port_range

    def get_gridftp_outgoing_port_range(self):
        outgoing_port_range = [
            int(x) for x in self.__get_list(
                ConfigFile.GRIDFTP_SECTION,
                ConfigFile.OUTGOING_PORT_RANGE_OPTION,
                1)]
        if len(outgoing_port_range) == 0:
            return None
        if len(outgoing_port_range) != 2:
            raise Exception("Invalid port range %s" % (
                    str(incoming_port_range)))
        return outgoing_port_range

    def get_gridftp_data_interface_option(self):
        data_interface = None
        if self.has_option(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.DATA_INTERFACE_OPTION):
            data_interface = self.get(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.DATA_INTERFACE_OPTION)
            if data_interface == '':
                data_interface = None
        return data_interface

    def get_gridftp_restrict_paths(self):
        restrict_paths = None
        if self.has_option(ConfigFile.GRIDFTP_SECTION,
                    ConfigFile.RESTRICT_PATHS_OPTION):
            restrict_paths = self.getboolean(
                    ConfigFile.GRIDFTP_SECTION,
                    ConfigFile.RESTRICT_PATHS_OPTION)
            if restrict_paths == '':
                restrict_paths = None
        return restrict_paths

    def get_gridftp_sharing_enabled(self):
        sharing_enabled = False
        if self.has_option(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SHARING_ENABLED_OPTION):
            sharing_enabled = self.get_boolen(
                    ConfigFile.GRIDFTP_SECTION,
                    ConfigFile.SHARING_ENABLED_OPTION)
        return sharing_enabled


    def get_gridftp_sharing_dn(self):
        sharing_dn = None
        if self.has_option(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SHARING_DN):
            sharing_dn = self.get(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SHARING_DN)
            if sharing_dn == '':
                sharing_dn = None
        if sharing_dn is None:
            sharing_dn = ConfigFile.DEFAULT_SHARING_DN

        return sharing_dn

    def get_gridftp_sharing_restrict_port(self):
        sharing_rp = None
        if self.has_option(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SHARING_RESTRICT_PORT):
            sharing_rp = self.get(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SHARING_RESTRICT_PORT)
            if sharing_rp == '':
                sharing_rp = None

        return sharing_rp

    def get_gridftp_sharing_file(self):
        sharing_file = None
        if self.has_option(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SHARING_FILE):
            sharing_file = self.get(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SHARING_FILE)
            if sharing_file == '':
                sharing_file = None

        return sharing_file

    def get_gridftp_sharing_file_control(self):
        sharing_file_control = False
        if self.has_option(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SHARING_FILE_CONTROL):
            sharing_file_control = self.get_boolen(
                    ConfigFile.GRIDFTP_SECTION,
                    ConfigFile.SHARING_FILE_CONTROL)
        return sharing_file_control

    def get_myproxy_server(self):
        myproxy_server = None
        if self.has_option(ConfigFile.MYPROXY_SECTION,
                ConfigFile.SERVER_OPTION):
            myproxy_server = self.get(ConfigFile.MYPROXY_SECTION,
                    ConfigFile.SERVER_OPTION)
            if myproxy_server == '':
                myproxy_server = None
            else:
                name = None
                if "://" in myproxy_server:
                    url = urlparse.urlparse(myproxy_server)
                    if ":" in url.netloc:
                        name = url.netloc.split(":")[0]
                    else:
                        name = url.netloc
                elif ":" in myproxy_server:
                    name = myproxy_server.split(":")[0]
                if name == "localhost":
                    myproxy_server = gcmu.public_hostname()
        return myproxy_server

    def get_myproxy_dn(self):
        myproxy_dn = None
        if self.has_option(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.DN_OPTION):
            myproxy_dn = self.get(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.DN_OPTION)
            if myproxy_dn == '':
                myproxy_dn = None

        return myproxy_dn

    def get_myproxy_endpoints(self):
        return self.__get_list(
                ConfigFile.MYPROXY_SECTION,
                ConfigFile.ENDPOINTS_OPTION)

    def get_myproxy_ca(self):
        myproxy_ca = False
        if self.has_option(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.CA_OPTION):
            myproxy_ca = self.getboolean(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.CA_OPTION)
            if myproxy_ca == '':
                myproxy_ca = False
        return myproxy_ca

    def get_myproxy_ca_directory(self):
        ca_dir = None

        if self.has_option(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.CA_DIRECTORY_OPTION):
            ca_dir = self.get(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.CA_DIRECTORY_OPTION)
            if ca_dir == '':
                ca_dir = None
        if ca_dir is None:
            ca_dir = os.path.join(
                self.root, "var", "lib", "gcmu", "myproxy-ca")
        return os.path.abspath(ca_dir)

    def get_myproxy_ca_passphrase(self):
        myproxy_ca_passphrase = None

        if self.has_option(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.CA_PASSPHRASE_OPTION):
            myproxy_ca_passphrase = self.get(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.CA_PASSPHRASE_OPTION)
            if myproxy_ca_passphrase == '':
                myproxy_ca_passphrase = None
        if myproxy_ca_passphrase is None:
            myproxy_ca_passphrase = 'globus'
        return myproxy_ca_passphrase

    def get_myproxy_use_pam_login(self):
        use_pam_login = False
        if self.has_option(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.USE_PAM_LOGIN_OPTION):
            use_pam_login = self.getboolean(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.USE_PAM_LOGIN_OPTION)
            if use_pam_login == '':
                use_pam_login = False
        return use_pam_login

    def get_myproxy_config_file(self):
        config_file = None

        if self.has_option(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.CONFIG_FILE_OPTION):
            config_file = self.get(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.CONFIG_FILE_OPTION)
            if config_file == '':
                config_file = None
        if config_file is None:
            config_file = os.path.join(
                self.root, 'etc', 'gcmu', 'myproxy-server.conf')

        return config_file
# vim: set syntax=python:
