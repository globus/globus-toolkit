#! /usr/bin/python

from distutils.core import setup
import os

version = "2.0.16"

versionfile_path = os.path.join("globus","connect","multiuser",
        "setup","version")
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
