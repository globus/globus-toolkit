#! /usr/bin/python

from distutils.core import setup

setup(name = 'globus_connect_multiuser',
    version = '2.0.10',
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
                'mapapp-template' ]
        },
    data_files = [( '/etc', [ 'globus-connect-multiuser.conf' ])],
    scripts = ['globus-connect-multiuser-setup'],
    )
