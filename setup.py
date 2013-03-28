#! /usr/bin/python

from distutils.core import setup
import os

setup(name = 'myproxy_oauth',
    version = '0.0',
    description = 'MyProxy OAuth Delegation Service',
    author = 'Globus Toolkit',
    author_email = 'support@globus.org',
    packages = [
            'myproxy',
            'myproxyoauth',
            'oauth2'],
    package_data = {
        'myproxyoauth': [ 'templates/*.html', 'static/*.png' ]
    },
    scripts = [ 'wsgi.py' ],
    data_files = [
            ('apache', [ 'conf/myproxy-oauth', 'conf/myproxy-oauth-2.4' ])],
)
