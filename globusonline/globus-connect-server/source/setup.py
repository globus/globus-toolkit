#! /usr/bin/python

from distutils.core import setup
import os

version = "3.0.6"

versionfile_path = os.path.join("globus","connect","server", "version")
oldversion = None
if os.path.exists(versionfile_path):
    oldversionfile = file(versionfile_path, "r")
    try:
        oldversion = oldversionfile.read().strip()
    finally:
        oldversionfile.close()

if version != oldversion:
    versionfile = file(versionfile_path, "w")
    try:
        versionfile.write(version + "\n")
    finally:
        versionfile.close()

setup(name = 'globus_connect_server',
    version = version,
    description = 'Globus Connect Server',
    author = 'Globus Toolkit',
    author_email = 'support@globus.org',
    url = 'https://www.globus.org/globus-connect-server',
    packages = [
            'globus',
            'globus.connect',
            'globus.connect.server',
            'globus.connect.server.io',
            'globus.connect.server.id',
            'globus.connect.server.web',
            'globus.connect.security'],
    package_data = {
        'globus.connect.security': [
                '*.pem',
                '*.signing_policy',
                'cilogon-crl-fetch'],
        'globus.connect.server': [
                'mapapp-template',
                'version'
        ]
        },
    data_files = [( '/etc', [ 'globus-connect-server.conf' ]),
                  ( '/usr/share/man/man8', [
                        'man/man8/globus-connect-server-setup.8',
                        'man/man8/globus-connect-server-cleanup.8',
                        'man/man8/globus-connect-server-id-setup.8',
                        'man/man8/globus-connect-server-id-cleanup.8',
                        'man/man8/globus-connect-server-io-setup.8',
                        'man/man8/globus-connect-server-io-cleanup.8',
                        'man/man8/globus-connect-server-web-setup.8',
                        'man/man8/globus-connect-server-web-cleanup.8'
                        ])],
    scripts = ['globus-connect-server-setup',
               'globus-connect-server-cleanup',
               'globus-connect-server-id-cleanup',
               'globus-connect-server-id-setup',
               'globus-connect-server-io-cleanup',
               'globus-connect-server-io-setup',
               'globus-connect-server-web-cleanup',
               'globus-connect-server-web-setup'
    ],
    )
