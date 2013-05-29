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

from subprocess import Popen, PIPE
from globusonline.transfer.api_client import TransferAPIClient
from globusonline.transfer.api_client import TransferAPIError

class Web(gcmu.GCMU):
    """
    Class to configure a MyProxy OAuth server
    """
    def __init__(self, **kwargs):
        super(Web, self).__init__(**kwargs)
        self.password = kwargs.get("password")
        self.enabled_mod_ssl = \
            "/var/lib/globus-connect-multiuser/enabled_mod_ssl"
        self.enabled_mod_wsgi = \
            "/var/lib/globus-connect-multiuser/enabled_mod_wsgi"
        self.enabled_default_ssl_site = \
            "/var/lib/globus-connect-multiuser/enabled_default_ssl_site"
        (distname, distver, distid) = platform.dist()

        if distname in [ 'Ubuntu', 'debian' ]:
            self.service = "apache2"
            self.dist_type = "deb"
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
            self.logger.info("copying " + css + " to " + 
                    '/usr/share/myproxy-oauth/myproxyoauth/static/site.css')
            shutil.copy(css,
                    '/usr/share/myproxy-oauth/myproxyoauth/static/site.css')
        logo = self.conf.get_oauth_logo()
        if logo is not None:
            self.logger.info("copying " + logo + " to " + 
                    '/usr/share/myproxy-oauth/myproxyoauth/static/')
            shutil.copy(logo,
                    '/usr/share/myproxy-oauth/myproxyoauth/static/')
        self.logger.debug("EXIT: Web.copy_auth_conf()")

    def remove_auth_conf(self, **kwargs):
        self.logger.debug("ENTER: Web.remove_auth_conf()")
        site_css = '/usr/share/myproxy-oauth/myproxyoauth/static/site.css'
        if os.path.exists(site_css):
            self.logger.info("removing site css from " + site_css)
            os.remove(site_css)
        site_logo = self.conf.get_oauth_logo()
        if site_logo is not None:
            installed_site_logo = os.path.join(
                '/usr/share/myproxy-oauth/myproxyoauth/static',
                os.path.basename(site_logo))
            if os.path.exists(installed_site_logo):
                self.logger.info("removing site logo from " + site_logo)
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
                    self.logger.info(out)
                if err != "":
                    self.logger.warn(err)
                touched = file(self.enabled_mod_ssl, "w")
                touched.close()
        self.logger.debug("EXIT: Web.enable_mod_ssl()")

    def enable_mod_wsgi(self, **kwargs):
        self.logger.debug("ENTER: Web.enable_mod_wsgi()")
        if self.dist_type == 'deb':
            if not os.path.exists("/etc/apache2/mods-available/mod_wsgi.load"):
                enabler = Popen(["/usr/sbin/a2enmod","wsgi"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (out, err) = enabler.communicate()
                if out != "":
                    self.logger.info(out)
                if err != "":
                    self.logger.warn(err)
                touched = file(self.enabled_mod_wsgi, "w")
                touched.close()
        self.logger.debug("EXIT: Web.enable_mod_wsgi()")

    def disable_mod_ssl(self, **kwargs):
        self.logger.debug("EXIT: Web.disable_mod_ssl()")
        if self.dist_type == 'deb':
            if os.path.exists(self.enabled_mod_ssl):
                disabler = Popen(["/usr/sbin/a2dismod","ssl"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (out, err) = disabler.communicate()
                if out != "":
                    self.logger.info(out)
                if err != "":
                    self.logger.warn(err)
                os.remove(self.enabled_mod_ssl)
        self.logger.debug("EXIT: Web.disable_mod_ssl()")

    def disable_mod_wsgi(self, **kwargs):
        self.logger.debug("EXIT: Web.disable_mod_wsgi()")
        if self.dist_type == 'deb':
            if os.path.exists(self.enabled_mod_wsgi):
                disabler = Popen(["/usr/sbin/a2dismod","wsgi"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (out, err) = disabler.communicate()
                if out != "":
                    self.logger.info(out)
                if err != "":
                    self.logger.warn(err)
                os.remove(self.enabled_mod_wsgi)
        self.logger.debug("EXIT: Web.disable_mod_wsgi()")

    def enable_default_ssl_site(self, **kwargs):
        if self.dist_type == 'deb':
            if not os.path.exists("/etc/apache2/sites-enabled/default-ssl"):
                enabler = Popen(["/usr/sbin/a2ensite","default-ssl"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (stdout, stderr) = enabler.communicate()
                touched = file(self.enabled_default_ssl_site, "w")
                touched.close()

    def disable_default_ssl_site(self, **kwargs):
        if self.dist_type == 'deb':
            if os.path.exists(self.enabled_default_ssl_site):
                disabler = Popen(["/usr/sbin/a2dissite","default-ssl"],
                        stdin=None, stdout=PIPE, stderr=PIPE)
                (stdout, stderr) = disabler.communicate()
                os.remove(self.enabled_default_ssl_site)

# vim: filetype=python:
