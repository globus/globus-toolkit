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
import globus.connect.server as gcmu

from subprocess import Popen, PIPE
from globusonline.transfer.api_client import TransferAPIClient
from globusonline.transfer.api_client import TransferAPIError

_enabled_mod_ssl = "/var/lib/globus-connect-server/enabled_mod_ssl"
_enabled_mod_wsgi = "/var/lib/globus-connect-server/enabled_mod_wsgi"
_enabled_default_ssl_site = \
        "/var/lib/globus-connect-server/enabled_default_ssl_site"
_enabled_myproxy_oauth_conf = \
        "/var/lib/globus-connect-server/enabled_myproxy_oauth_conf"
_created_vhost_conf = "/var/lib/globus-connect-server/created_vhost_conf"
_created_ssl_cert = "/var/lib/globus-connect-server/created_ssl_cert"
_created_pidfile_symlink = "/var/lib/globus-connect-server/created_pidfile_symlink"

_suse_ssl_cert = "/etc/apache2/ssl.crt/server.crt"
_suse_ssl_key = "/etc/apache2/ssl.key/server.key"
_suse_ssl_req = "/etc/apache2/ssl.csr/server.csr"
_suse_ssl_template = "/etc/apache2/vhosts.d/vhost-ssl.template"
_suse_ssl_conf = "/etc/apache2/vhosts.d/vhost-ssl.conf"
_suse_pidfile_link_name = "/var/run/httpd2.pid"
_suse_pidfile_real_name = "/var/run/httpd.pid"

class Web(gcmu.GCMU):

    """
    Class to configure a MyProxy OAuth server
    """
    def __init__(self, **kwargs):
        super(Web, self).__init__(**kwargs)
        self.password = kwargs.get("password")
        (distname, distver, distid) = platform.dist()

        if distname == 'debian':
            self.service = "apache2"
            self.dist_type = "deb"
            self.http_conf_dir = '/etc/apache2/conf.d'
        elif distname == 'Ubuntu':
            self.service = "apache2"
            self.dist_type = "deb"
            if float(distver) > 14:
                self.http_conf_dir = '/etc/apache2/conf-available'
            else:
                self.http_conf_dir = '/etc/apache2/conf.d'
        elif distname == 'SuSE':
            self.service = "apache2"
            self.dist_type = "suse"
            self.http_conf_dir = '/etc/apache2/conf.d'
        else:
            self.service = "httpd"
            self.dist_type = "rpm"
            self.http_conf_dir = '/etc/httpd/conf.d'

    def is_local(self):
        return self.is_local_oauth()

    def setup(self, **kwargs):
        self.logger.debug("ENTER: Web.setup()")

        if not self.is_local():
            if self.conf.get_security_identity_method() == self.conf.IDENTITY_METHOD_OAUTH:
                print "Using remote OAuth server " \
                    + self.conf.get_oauth_server()
            self.logger.debug("No OAuth server to configure on this node")
            return

        self.copy_auth_conf(**kwargs)
        self.register_oauth_server(**kwargs)
        self.enable_mod_ssl(**kwargs)
        self.enable_mod_wsgi(**kwargs)
        self.enable_default_ssl_site(**kwargs)
        self.configure_trust_roots(**kwargs)
        self.restart(**kwargs)
        self.enable(**kwargs)
        print "Configured OAuth server " + self.conf.get_oauth_server()

        self.logger.debug("EXIT: Web.setup()")

    def cleanup(self, **kwargs):
        if not self.is_local():
            self.logger.debug("web cleanup: no OAuth server configured")
            return
        self.disable_default_ssl_site(**kwargs)
        self.disable_default_ssl_site(**kwargs)
        self.remove_auth_conf(**kwargs)
        self.disable_mod_ssl(**kwargs)
        self.disable_mod_wsgi(**kwargs)
        self.restart(**kwargs)

    def copy_auth_conf(self, **kwargs):
        self.logger.debug("ENTER: Web.copy_auth_conf()")
        css = self.conf.get_oauth_stylesheet()
        if css is not None:
            self.logger.debug("copying " + css + " to " + 
                    '/usr/share/myproxy-oauth/myproxyoauth/static/site.css')
            shutil.copy(css,
                    '/usr/share/myproxy-oauth/myproxyoauth/static/site.css')
        logo = self.conf.get_oauth_logo()
        if logo is not None:
            self.logger.debug("copying " + logo + " to " + 
                    '/usr/share/myproxy-oauth/myproxyoauth/static/')
            shutil.copy(logo,
                    '/usr/share/myproxy-oauth/myproxyoauth/static/')
        self.logger.debug("EXIT: Web.copy_auth_conf()")

    def remove_auth_conf(self, **kwargs):
        self.logger.debug("ENTER: Web.remove_auth_conf()")
        site_css = '/usr/share/myproxy-oauth/myproxyoauth/static/site.css'
        if os.path.exists(site_css):
            self.logger.debug("removing site css from " + site_css)
            os.remove(site_css)
        site_logo = self.conf.get_oauth_logo()
        if site_logo is not None:
            installed_site_logo = os.path.join(
                '/usr/share/myproxy-oauth/myproxyoauth/static',
                os.path.basename(site_logo))
            if os.path.exists(installed_site_logo):
                self.logger.debug("removing site logo from " + site_logo)
                os.remove(installed_site_logo)
        self.logger.debug("EXIT: Web.remove_auth_conf()")
        
    def register_oauth_server(self, **kwargs):
        self.logger.debug("ENTER: Web.register_oauth_server()")
        oauth_server = self.conf.get_oauth_server()
        user = self.api.username
        myproxy_server = self.conf.get_myproxy_server()
        if myproxy_server is None:
            raise Exception("Attempting to register OAuth with no MyProxy server defined")
        args = ["/usr/sbin/myproxy-oauth-setup", "-s", "-u",
                user, "-m", myproxy_server, "-o", oauth_server]
        if self.conf.get_go_instance() == "Test":
            args.append("-n")
            args.append("graph.api.test.globuscs.info")
        self.logger.debug("executing " + " ".join(args))
        setup = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        (out, err) = setup.communicate(self.password)
        if out != "":
            self.logger.debug(out)
        if err != "":
            self.logger.warn(err)
        self.logger.debug("EXIT: Web.register_oauth_server()")

    def enable_mod_ssl(self, **kwargs):
        self.logger.debug("ENTER: Web.enable_mod_ssl()")
        if self.dist_type == 'deb':
            if not os.path.exists("/etc/apache2/mods-available/mod_ssl.load"):
                enabler = Popen(["/usr/sbin/a2enmod","ssl"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (out, err) = enabler.communicate()
                if out != "":
                    self.logger.debug(out)
                if err != "":
                    self.logger.warn(err)
                touched = file(_enabled_mod_ssl, "w")
                touched.close()
        elif self.dist_type == 'suse':
            modlist = Popen(["/sbin/yast2","http-server", "modules", "list"],
                    stdin=None, stdout=PIPE, stderr=PIPE)
            (out, err) = modlist.communicate()
            ssl_already_enabled = False
            for l in err.split("\n"):
                if "\t" in l:
                    status, module = l.strip().split("\t")
                    if module == 'ssl' and status == 'Enabled':
                        ssl_already_enabled = True
                        break
            if not ssl_already_enabled:
                enabler = Popen(["/sbin/yast2","http-server", "modules",
                        "enable=ssl"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (out, err) = enabler.communicate()
                if out != "":
                    self.logger.debug(out)
                if err != "":
                    self.logger.warn(err)
                touched = file(_enabled_mod_ssl, "w")
                touched.close()
            # Workaround inconsistent pid file naming in the init script
            if not (os.path.exists(_suse_pidfile_link_name) or
                    os.path.islink(_suse_pidfile_link_name)):
                os.symlink(_suse_pidfile_real_name, _suse_pidfile_link_name)
                touched = file(_created_pidfile_symlink, "w")
                touched.close()

    def enable_mod_wsgi(self, **kwargs):
        self.logger.debug("ENTER: Web.enable_mod_wsgi()")
        if self.dist_type == 'deb':
            if not os.path.exists("/etc/apache2/mods-available/mod_wsgi.load"):
                enabler = Popen(["/usr/sbin/a2enmod","wsgi"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (out, err) = enabler.communicate()
                if out != "":
                    self.logger.debug(out)
                if err != "":
                    self.logger.warn(err)
                touched = file(_enabled_mod_wsgi, "w")
                touched.close()
            if self.http_conf_dir == '/etc/apache2/conf-available' and not \
                    os.path.exists(
                    "/etc/apache2/conf-available/myproxy-oauth.conf"):
                enabler = Popen(["/usr/sbin/a2enconf", "myproxy-oauth"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (out, err) = enabler.communicate()
                if out != "":
                    self.logger.debug(out)
                if err != "":
                    self.logger.warn(err)
                touched = file(_enabled_myproxy_oauth_conf, "w")
                touched.close()

        self.logger.debug("EXIT: Web.enable_mod_wsgi()")

    def disable_mod_ssl(self, **kwargs):
        self.logger.debug("EXIT: Web.disable_mod_ssl()")
        if self.dist_type == 'deb':
            if os.path.exists(_enabled_mod_ssl):
                disabler = Popen(["/usr/sbin/a2dismod","ssl"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (out, err) = disabler.communicate()
                if out != "":
                    self.logger.debug(out)
                if err != "":
                    self.logger.warn(err)
                os.remove(_enabled_mod_ssl)
        elif self.dist_type == 'suse':
            if os.path.exists(_enabled_mod_ssl):
                disabler =  Popen(["/sbin/yast2","http-server", "module",
                        "disable=ssl"], stdin=None, stdout=PIPE, stderr=PIPE)
                (out, err) = disabler.communicate()
                if out != "":
                    self.logger.debug(out)
                if err != "":
                    self.logger.warn(err)
                os.remove(_enabled_mod_ssl)
            if os.path.exists(_created_pidfile_symlink):
                os.remove(_suse_pidfile_link_name)
                os.remove(_created_pidfile_symlink)
        self.logger.debug("EXIT: Web.disable_mod_ssl()")

    def disable_mod_wsgi(self, **kwargs):
        self.logger.debug("EXIT: Web.disable_mod_wsgi()")
        if self.dist_type == 'deb':
            if os.path.exists(_enabled_mod_wsgi):
                disabler = Popen(["/usr/sbin/a2dismod","wsgi"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (out, err) = disabler.communicate()
                if out != "":
                    self.logger.debug(out)
                if err != "":
                    self.logger.warn(err)
                os.remove(_enabled_mod_wsgi)
            if os.path.exists(_enabled_myproxy_oauth_conf):
                disabler = Popen(["/usr/sbin/a2disconf", "myproxy-oauth"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (out, err) = disabler.communicate()
                if out != "":
                    self.logger.debug(out)
                if err != "":
                    self.logger.warn(err)
                os.remove(_enabled_myproxy_oauth_conf)
        self.logger.debug("EXIT: Web.disable_mod_wsgi()")

    def enable_default_ssl_site(self, **kwargs):
        if self.dist_type == 'deb':
            if not os.path.exists("/etc/apache2/sites-enabled/default-ssl"):
                enabler = Popen(["/usr/sbin/a2ensite","default-ssl"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (stdout, stderr) = enabler.communicate()
                touched = file(_enabled_default_ssl_site, "w")
                touched.close()
        elif self.dist_type == 'suse':
            if not os.path.exists(_suse_ssl_conf):
                shutil.copy(_suse_ssl_template, _suse_ssl_conf)
                touched = file(_created_vhost_conf, "w")
                touched.close()

            if not os.path.exists(_suse_ssl_cert):
                ssl_create = Popen(["/usr/bin/gensslcert"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (out, err) = ssl_create.communicate()
                if out != "":
                    self.logger.debug(out)
                if err != "":
                    self.logger.warn(err)
                touched = file(_created_ssl_cert, "w")
                touched.close()


    def disable_default_ssl_site(self, **kwargs):
        if self.dist_type == 'deb':
            if os.path.exists(_enabled_default_ssl_site):
                disabler = Popen(["/usr/sbin/a2dissite","default-ssl"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (stdout, stderr) = disabler.communicate()
                os.remove(_enabled_default_ssl_site)
        elif self.dist_type == 'suse':
            if os.path.exists(_created_vhost_conf):
                os.remove(_suse_ssl_conf)
                os.remove(_created_vhost_conf)
            if os.path.exists(_created_ssl_cert):
                os.remove(_suse_ssl_cert)
                os.remove(_suse_ssl_key)
                os.remove(_suse_ssl_req)
                os.remove(_created_ssl_cert)

# vim: filetype=python:
