myproxyoauth-server
===================

MyProxy OAuth Delegation Service in Python

The MyProxy Delegation Service is a Python implementation of MyProxy OAuth
protocol, https://docs.google.com/document/pub?id=10SC7oSURc-EgxMQjcCS50gz0u2HzDJAFiG5hEHiSdxA.
The package depends on Flask and SQLAlchemy. The service can be deployed to
Apache with mod_wsgi. An examplary configuration file for Apache is in conf/.
The file should be copied to /etc/apache2/conf.d/ on Debian-based systems, or
to /etc/httpd/conf.d/ on Red Hat-based system. For security reasons, Apache runs
the service as the 'globus' user.

By default, the service uses SQLite3 database. A path to the database file is set
in myproxyoauth/myproxy-oauth/database.py. The directory with the database file must be
writable by the 'globus' user.

To generate web pages, the service uses templates stored in
myproxyoauth/templates/. The templates, and other static files stored in
myproxyoauth/static/ like images or cascade style sheets can be easily edited
and displayed directly in a web browser. The templates are accessible at
https://hostname/oauth/templates/, and the static files at https://hostname/oauth/static/.

To use the service with Globus Online, Globus Online that acts here as an OAuth
client has to be registered with the service first. To trigger the registration
workflow, go to https://hostname/oauth/configure. A Globus Online user
specified in the registration form will become an admin of the service.

Prerequisite packages on Debian-based systems:

python
python-openssl
python-flask
python-sqlalchemy
libapache2-mod-wsgi

