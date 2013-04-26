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
import globus.connect.multiuser as gcmu
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
    AUTHORIZATION_METHOD_OPTION = "AuthorizationMethod"
    AUTHORIZATION_METHOD_MYPROXY_GRIDMAP_CALLOUT = "MyProxyGridmapCallout"
    AUTHORIZATION_METHOD_CILOGON = "CILogon"
    AUTHORIZATION_METHODS = [
        AUTHORIZATION_METHOD_MYPROXY_GRIDMAP_CALLOUT,
        AUTHORIZATION_METHOD_CILOGON
    ]
    CILOGON_IDENTITY_PROVIDER = "CILogonIdentityProvider"
    GRIDMAP_FILE = "GridmapFile"
    
    SERVER_OPTION = "Server"
    SERVER_BEHIND_NAT_OPTION = "ServerBehindNAT"
    INCOMING_PORT_RANGE_OPTION = "IncomingPortRange"
    OUTGOING_PORT_RANGE_OPTION= "OutgoingPortRange"
    DATA_INTERFACE_OPTION = "DataInterface"
    RESTRICT_PATHS_OPTION = "RestrictPaths"
    SHARING_ENABLED_OPTION = "Sharing"
    SHARING_DN = "SharingDN"
    SHARING_RESTRICT_PATHS = "SharingRestrictPaths"
    SHARING_DIR = "SharingStateDir"
    SHARING_CONTROL = "SharingControl"
    DEFAULT_SHARING_DN = "/C=US/O=Globus Consortium/OU=Globus Connect User" + \
        "/CN=__transfer__"
    DN_OPTION = "DN"
    CA_OPTION = "CA"
    CA_DIRECTORY_OPTION = "CaDirectory"
    CA_PASSPHRASE_OPTION = "CaPassphrase"
    USE_PAM_LOGIN_OPTION = "UsePamLogin"
    CA_SUBJECT_DN_OPTION = "CaSubjectDN"
    CONFIG_FILE_OPTION = "ConfigFile"

    DEFAULT_CONFIG_FILE = os.path.join("etc","globus-connect-multiuser.conf")
    DEFAULT_DIR = os.path.join("var","lib", "globus-connect-multiuser")
    DEFAULT_SECURITY_DIR = os.path.join(DEFAULT_DIR, "grid-security")
    DEFAULT_CADIR = os.path.join(DEFAULT_SECURITY_DIR, "certificates")
    DEFAULT_GRIDMAP = os.path.join(DEFAULT_SECURITY_DIR, "grid-mapfile")
    DEFAULT_MYPROXY_CADIR = os.path.join(DEFAULT_DIR, "myproxy-ca")
    DEFAULT_CERT_FILE = os.path.join(DEFAULT_SECURITY_DIR, "hostcert.pem")
    DEFAULT_KEY_FILE = os.path.join(DEFAULT_SECURITY_DIR, "hostkey.pem")
    DEFAULT_GRIDMAP_FILE = os.path.join(DEFAULT_SECURITY_DIR, "grid-mapfile")

    def __init__(self, root="/", config_file=None):
        defaults = copy.copy(os.environ)
        defaults["HOSTNAME"] = gcmu.public_name()
        if "SHORT_HOSTNAME" not in defaults:
            defaults["SHORT_HOSTNAME"] = defaults["HOSTNAME"].split(".")[0]
        if "USER" in defaults:
            del defaults["USER"]
        if "GLOBUSONLINE_USER" not in defaults:
            defaults["GLOBUSONLINE_USER"] = ""
        if "GLOBUSONLINE_PASSWORD" not in defaults:
            defaults["GLOBUSONLINE_PASSWORD"] = ""

        ConfigParser.ConfigParser.__init__(self, defaults)
        self.root = root
        if config_file is None:
            config_file = os.path.join("/", ConfigFile.DEFAULT_CONFIG_FILE)
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

    def get(self, section, option):
        res_str = ''
        if self.has_option(section, option):
            res_str = ConfigParser.ConfigParser.get(self, section, option)
            if len(res_str) > 1 and res_str[0] == '"' and res_str[-1] == '"':
                res_str = res_str[1:-1]
        return res_str

    def get_go_username(self):
        user_name = None
        if self.has_option(
                ConfigFile.GLOBUSONLINE_SECTION,
                ConfigFile.USER_OPTION):
            user_name = self.get(
                ConfigFile.GLOBUSONLINE_SECTION,
                ConfigFile.USER_OPTION)
        if user_name == '':
            user_name = None

        return user_name

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
                name = None
        if name is None:
            name = gcmu.public_name().split(".")[0]
        elif "#" in name:
            name = name[name.find("#")+1:]
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

    def get_security_fetch_credential_from_relay(self):
        fetch_credential_from_relay = True
        if self.has_option(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.FETCH_CREDENTIAL_FROM_RELAY_OPTION):
            fetch_credential_from_relay = self.getboolean(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.FETCH_CREDENTIAL_FROM_RELAY_OPTION)
        return fetch_credential_from_relay

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
            certificate = os.path.join(self.root, ConfigFile.DEFAULT_CERT_FILE)
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
            key = os.path.join(self.root, ConfigFile.DEFAULT_KEY_FILE)
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
            cadir = os.path.join(self.root, ConfigFile.DEFAULT_CADIR)
        return os.path.abspath(cadir)

    def get_security_authorization_method(self):
        authorization_method = ''
        if self.has_option(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.AUTHORIZATION_METHOD_OPTION):
            authorization_method = self.get(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.AUTHORIZATION_METHOD_OPTION)
        if authorization_method == '':
            authorization_method = ConfigFile.AUTHORIZATION_METHODS[0]
        if authorization_method not in ConfigFile.AUTHORIZATION_METHODS:
            raise Exception("Unknown Security.AuthorizationMethod %s" \
                % (authorization_method))
        return authorization_method

    def get_security_cilogon_identity_provider(self):
        cilogon_idp = None
        if self.has_option(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.CILOGON_IDENTITY_PROVIDER):
            cilogon_idp = self.get(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.CILOGON_IDENTITY_PROVIDER)
            if cilogon_idp == '':
                cilogon_idp = None
        return cilogon_idp

    def get_security_gridmap_file(self):
        gridmap_file = None
        if self.has_option(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.GRIDMAP_FILE):
            gridmap_file = self.get(
                ConfigFile.SECURITY_SECTION,
                ConfigFile.GRIDMAP_FILE)
            if gridmap_file == '':
                gridmap_file = None
        if gridmap_file is None:
            gridmap_file = os.path.join(
                self.root, ConfigFile.DEFAULT_GRIDMAP_FILE)
        return gridmap_file

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

    def get_gridftp_server_behind_nat(self):
        server_behind_nat = False
        if self.has_option(
                ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SERVER_BEHIND_NAT_OPTION):
            server_behind_nat = self.getboolean(
                ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SERVER_BEHIND_NAT_OPTION)
        return server_behind_nat

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

    def get_gridftp_incoming_port_range(self):
        incoming_port_range = [
            int(x) for x in self.__get_list(
                ConfigFile.GRIDFTP_SECTION,
                ConfigFile.INCOMING_PORT_RANGE_OPTION,
                1)]
        if len(incoming_port_range) == 0:
            return [50000, 51000]
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

    def get_gridftp_data_interface(self):
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
            restrict_paths = self.get(
                    ConfigFile.GRIDFTP_SECTION,
                    ConfigFile.RESTRICT_PATHS_OPTION)
            if restrict_paths == '':
                restrict_paths = None
        return restrict_paths

    def get_gridftp_sharing_enabled(self):
        sharing_enabled = False
        if self.has_option(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SHARING_ENABLED_OPTION):
            sharing_enabled = self.getboolean(
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

    def get_gridftp_sharing_restrict_paths(self):
        sharing_rp = None
        if self.has_option(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SHARING_RESTRICT_PATHS):
            sharing_rp = self.get(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SHARING_RESTRICT_PATHS)
            if sharing_rp == '':
                sharing_rp = None

        return sharing_rp

    def get_gridftp_sharing_state_dir(self):
        sharing_dir = None
        if self.has_option(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SHARING_DIR):
            sharing_dir = self.get(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SHARING_DIR)
        return sharing_dir

    def get_gridftp_sharing_control(self):
        sharing_control = True
        if self.has_option(ConfigFile.GRIDFTP_SECTION,
                ConfigFile.SHARING_CONTROL):
            sharing_control = self.getboolean(
                    ConfigFile.GRIDFTP_SECTION,
                    ConfigFile.SHARING_CONTROL)
        return sharing_control

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

    def get_myproxy_server_behind_nat(self):
        server_behind_nat = False
        if self.has_option(
                ConfigFile.MYPROXY_SECTION,
                ConfigFile.SERVER_BEHIND_NAT_OPTION):
            server_behind_nat = self.getboolean(
                ConfigFile.MYPROXY_SECTION,
                ConfigFile.SERVER_BEHIND_NAT_OPTION)
        return server_behind_nat

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

    def get_myproxy_ca(self):
        myproxy_ca = True
        if self.has_option(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.CA_OPTION):
            myproxy_ca = self.getboolean(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.CA_OPTION)
            if myproxy_ca == '':
                myproxy_ca = True
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
            ca_dir = os.path.join(self.root, ConfigFile.DEFAULT_MYPROXY_CADIR)
        return os.path.abspath(ca_dir)

    def get_myproxy_ca_passphrase(self):
        myproxy_ca_passphrase = None

        if self.has_option(
                ConfigFile.MYPROXY_SECTION, ConfigFile.CA_PASSPHRASE_OPTION):
            myproxy_ca_passphrase = self.get(
                    ConfigFile.MYPROXY_SECTION, ConfigFile.CA_PASSPHRASE_OPTION)
        if myproxy_ca_passphrase == '':
            myproxy_ca_passphrase = None
        if myproxy_ca_passphrase is None:
            myproxy_ca_passphrase = 'globus'
        return myproxy_ca_passphrase
    
    def get_myproxy_ca_subject_dn(self):
        myproxy_ca_subject_dn = None
        if self.has_option(
                ConfigFile.MYPROXY_SECTION, ConfigFile.CA_SUBJECT_DN_OPTION):
            myproxy_ca_subject_dn = self.get(
                    ConfigFile.MYPROXY_SECTION, ConfigFile.CA_SUBJECT_DN_OPTION)
        if myproxy_ca_subject_dn == '':
            myproxy_ca_subject_dn = None
        return myproxy_ca_subject_dn

    def get_myproxy_use_pam_login(self):
        use_pam_login = True
        if self.has_option(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.USE_PAM_LOGIN_OPTION):
            use_pam_login = self.getboolean(
                    ConfigFile.MYPROXY_SECTION,
                    ConfigFile.USE_PAM_LOGIN_OPTION)
            if use_pam_login == '':
                use_pam_login = True
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
                self.root, ConfigFile.DEFAULT_DIR, 'myproxy-server.conf')
        return config_file

    def get_myproxy_init_config_file(self):
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
                self.root, ConfigFile.DEFAULT_DIR, 'myproxy-server.conf')
        return config_file

    def get_etc_gridftp_d(self):
        return os.path.join(self.root, "etc", "gridftp.d")

    def get_var_gridftp_d(self):
        return os.path.join(self.root, ConfigFile.DEFAULT_DIR, 'gridftp.d')

    def get_etc_myproxy_d(self):
        return os.path.join(self.root, "etc", "myproxy.d")

    def get_var_myproxy_d(self):
        return os.path.join(self.root, ConfigFile.DEFAULT_DIR, 'myproxy.d')

# vim: syntax=python: nospell:
