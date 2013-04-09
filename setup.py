#! /usr/bin/python

from distutils.core import setup
import os
import platform

(platname, platver, platid) = platform.dist()

confdir="sysconfig"
if platname is not None:
    if platname == "debian" or platname == "ubuntu":
        confdir="default"

setup(name = 'myproxy_oauth',
    version = '0.3',
    description = 'MyProxy OAuth Delegation Service',
    author = 'Globus Toolkit',
    author_email = 'support@globus.org',
    packages = [
            'myproxy',
            'myproxyoauth',
            'myproxyoauth.templates',
            'myproxyoauth.static',
            'oauth2'],
    package_data = {
        'myproxyoauth': [ 'templates/*.html', 'static/*.png' ]
    },
    scripts = [ 'wsgi.py' ],
    data_files = [
            ('apache', [ 'conf/myproxy-oauth', 'conf/myproxy-oauth-2.4' ]),
            ('init.d', [ 'init/myproxy-oauth'] ),
            ( confdir, [ 'sysconfig/myproxy-oauth'])]
)
