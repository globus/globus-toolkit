#! /usr/bin/python

from distutils.core import setup

setup(name = 'gcmu',
    version = '2.0',
    description = 'Globus Connect Multi-User',
    author = 'Globus Toolkit',
    author_email = 'support@globus.org',
    url = 'https://www.globusonline.org/gcmu',
    packages = ['gcmu', 'gcmu.setup'],
    package_data = {
        'gcmu': [ '*.pem', '*.signing_policy', 'mapapp-template' ]
        },
    data_files = [( '/etc', [ 'gcmu.conf' ])],
    scripts = ['gcmu-setup-endpoint', 'gcmu-setup-services'],
    )
