#! /usr/bin/python

from distutils.core import setup
import os

version = "2.0.14"

versionfile = file(
        os.path.join("globus","connect","multiuser","setup","version"), "w")
versionfile.write(version + "\n")
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
            'globus.connect.multiuser.setup',
            'globus.connect.security'],
    package_data = {
        'globus.connect.security': [
                '*.pem',
                '*.signing_policy'],
        'globus.connect.multiuser': [
                'mapapp-template' ],
        'globus.connect.multiuser.setup': [
                'version'
        ]
        },
    data_files = [( '/etc', [ 'globus-connect-multiuser.conf' ])],
    scripts = ['globus-connect-multiuser-setup'],
    )
