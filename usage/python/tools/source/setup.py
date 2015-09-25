#! /usr/bin/python

from distutils.core import setup

setup(name = 'globus_usage_tools',
    version = '0.15',
    description = 'Globus Usage Collector Tools',
    author = 'Globus Toolkit',
    author_email = 'support@globus.org',
    url = 'http://www.globus.org/toolkit/usagestats_server',
    packages = ['globus', 'globus.usage'],
    scripts = ['globus-usage-collector', 'globus-usage-uploader', 'globus-usage-aggregator'],
    data_files = [
        ('share/man/man8', ['globus-usage-collector.8', 'globus-usage-uploader.8']),
        ('share/globus-usage-tools', ['usage-tables.sql', 'usage-views.sql', 'usage-aggregation-tables.sql'] ),
        ('share/doc/globus-usage-tools', ['README.txt', 'index.html']),
        ('share/doc/globus-usage-tools/examples', ['usagestats.cron']),
        ('etc/globus', ['usage-tools.conf']),
        ('etc/init.d', ['init/globus-usage-collector'])]
    )
