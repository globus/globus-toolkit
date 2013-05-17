#! /usr/bin/python

from distutils.core import setup
import os

version = "2.0.33"

versionfile_path = os.path.join("globus","connect","multiuser", "version")
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

setup(name = 'globus_connect_multiuser',
    version = version,
    description = 'Globus Connect Multi-User',
    author = 'Globus Toolkit',
    author_email = 'support@globus.org',
    url = 'https://www.globusonline.org/gcmu',
    packages = [
            'globus',
            'globus.connect',
            'globus.connect.multiuser',
            'globus.connect.multiuser.io',
            'globus.connect.multiuser.id',
            'globus.connect.multiuser.web',
            'globus.connect.security'],
    package_data = {
        'globus.connect.security': [
                '*.pem',
                '*.signing_policy',
                'cilogon-crl-fetch'],
        'globus.connect.multiuser': [
                'mapapp-template',
                'version'
        ]
        },
    data_files = [( '/etc', [ 'globus-connect-multiuser.conf' ]),
                  ( '/usr/share/man/man8', [
                        'man/man8/globus-connect-multiuser-setup.8',
                        'man/man8/globus-connect-multiuser-cleanup.8',
                        'man/man8/globus-connect-multiuser-id-setup.8',
                        'man/man8/globus-connect-multiuser-id-cleanup.8',
                        'man/man8/globus-connect-multiuser-io-setup.8',
                        'man/man8/globus-connect-multiuser-io-cleanup.8',
                        'man/man8/globus-connect-multiuser-web-setup.8',
                        'man/man8/globus-connect-multiuser-web-cleanup.8'
                        ])],
    scripts = ['globus-connect-multiuser-setup',
               'globus-connect-multiuser-cleanup',
               'globus-connect-multiuser-id-cleanup',
               'globus-connect-multiuser-id-setup',
               'globus-connect-multiuser-io-cleanup',
               'globus-connect-multiuser-io-setup',
               'globus-connect-multiuser-web-cleanup',
               'globus-connect-multiuser-web-setup'
    ],
    )
