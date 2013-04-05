#
# Copyright 2010-2011 University of Chicago
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import socket
import cgi
import random
import base64
import httplib
import json
import time
import oauth2 as oauth
import Crypto.PublicKey.RSA
import myproxy
import jinja2
import pkgutil
import os
from myproxyoauth import application
from myproxyoauth.database import db_session, Admin, Client, Transaction
from urllib import quote


def get_template(name):
    template_data = None
    if hasattr(pkgutil, "get_data"):
        template_data = pkgutil.get_data("myproxyoauth.templates", name)
    else:
        import myproxyoauth.templates
        template_path = os.path.join(
            os.path.dirname(myproxyoauth.templates.__file__), name)
        template_file = file(template_path, "r")
        try:
            template_data = template_file.read()
        finally:
            template_file.close()
    return jinja2.Template(template_data)
        

def render_template(name, **kwargs):
    template = get_template(name)
    return template.render(**kwargs).encode("utf-8")

def url_reconstruct(environ):
    url = environ['wsgi.url_scheme']+'://'

    if environ.get('HTTP_HOST'):
        url += environ['HTTP_HOST']
    else:
        url += environ['SERVER_NAME']

        if environ['wsgi.url_scheme'] == 'https':
            if environ['SERVER_PORT'] != '443':
               url += ':' + environ['SERVER_PORT']
        else:
            if environ['SERVER_PORT'] != '80':
               url += ':' + environ['SERVER_PORT']

    url += quote(environ.get('SCRIPT_NAME', ''))
    url += quote(environ.get('PATH_INFO', ''))
    if environ.get('QUERY_STRING'):
        url += '?' + environ['QUERY_STRING']
    return url

@application.route('/test')
def test(environ, start_response):
    status = "403 Forbidden"
    headers = [("Content-Type", "text/plain")]
    start_response(status, headers)
    return "bad"

@application.teardown_request
def shutdown_session(exception=None):
    db_session.remove()

"""
Register Globus Online OAuth with the server. The registration consists of two
steps:
1. Get an OAuth access token from Globus Online.
2. Trigger a Globus Online client registration with the service.
"""

@application.route('/configure', methods=['GET'])
def get_configure(environ, start_response):
    name = environ.get("HTTP_HOST")
    if name is None or name == "":
        name = socket.gethostname()
        if name.find('.') ==  -1:
            name = socket.gethostbyaddr(name)[0]
    headers = [("Content-Type", "text/html")]
    body = render_template('configure.html', hostname=name)
    start_response("200 Ok", headers)
    return body

@application.route('/configure', methods=['POST'])
def post_configure(environ, start_response):
    request = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ)

    username = request.getvalue('username').encode('utf-8')
    password = request.getvalue('password').encode('utf-8')
    oauth_server = request.getvalue('oauth_server').encode('utf-8')
    myproxy_server = request.getvalue('myproxy_server').encode('utf-8')
    nexus_server = request.getvalue('nexus_server').encode('utf-8')

    admin = db_session.query(Admin).first()

    if admin is not None:
        if admin.username != username:
            message = 'You are not an admin of the MyProxy Delegation Service'
            status = "500 Internal Server Error"
            headers = [
                    ("X-Error-Message", message),
                    ("Content-Type", "text/html") ]
            start_response(status, headers)
            return render_template('configure_error.html', message=message)

    try:
        access_token = get_access_token(username, password, nexus_server)
    except Exception, e:
        message='Could not get access token. %s' % str(e)
        status = "500 Internal Server Error"
        headers = [
                ("X-Error-Message", message),
                ("Content-Type", "text/html") ]
        start_response(status, headers)
        return render_template('configure_error.html', message=message)

    client_id = 'myproxy:oa4mp,2012:/client/' \
        + ''.join([random.choice('0123456789abcdef') for i in range(32)])
    try:
        (home_url, gateway_name, oauth_consumer_id, public_key) = register_go(
                nexus_server, access_token, client_id, oauth_server)
    except Exception, e:
        message = str(e)
        status = "500 Internal Server Error"
        headers = [
                ("X-Error-Message", message),
                ("Content-Type", "text/html") ]
        start_response(status, headers)
        return render_template('configure_error.html', message=message)

    application.logger.debug('Registered: gateway_name: %s, home_url: %s,'
            ' oauth_consumer_id: %s'
            % (gateway_name, home_url, oauth_consumer_id))

    if admin is None:
        db_session.add(Admin(username))

    client = db_session.query(Client).\
            filter(Client.oauth_consumer_key==oauth_consumer_id).first()
    if client is None:
        client = Client()
    client.oauth_consumer_key=oauth_consumer_id
    client.oauth_client_pubkey=public_key
    client.name=gateway_name
    client.home_url=home_url
    client.myproxy_server=myproxy_server
    db_session.add(client)

    db_session.commit()

    status = "200 Ok"
    headers = [
            ("Content-Type", "text/html") ]

    res = render_template('configure_ok.html', gateway_name=gateway_name,
            home_url=home_url, oauth_consumer_id=oauth_consumer_id,
            public_key=public_key)
    start_response(status, headers)
    return res

def get_access_token(username, password, server):
    """
    Get an access token from Globus Online Nexus.
    Returns: an access token
    """

    basic_auth = base64.b64encode('%s:%s' % (username, password))
    headers = { 'Content-type': 'app/json; charset=UTF-8',
            'Hostname': server,
            'Accept': 'app/json; charset=UTF-8',
            'Authorization': 'Basic %s' % basic_auth }
    c = httplib.HTTPSConnection(server, 443)
    c.request('GET', '/goauth/token?grant_type=client_credentials',
            headers=headers)
    response = c.getresponse()
    json_reader = None
    if hasattr(json, 'loads'):
        json_reader = json.loads
    elif hasattr(json, 'JsonReader'):
        json_reader_obj = json.JsonReader()
        json_reader = json_reader_obj.read

    if response.status == 403:
        try :
            message = json_reader(response.read()).get('message')
        except Exception, e:
            message = str(e)
        raise Exception('403 Error: %s' % message)
    elif response.status > 299 or response.status < 200:
        raise Exception('%d Error: %s' % (response.status, response.reason))
    data = json_reader(response.read())
    token = data.get('access_token')
    if token is None:
        raise Exception('No access token in response')
    return token


def register_go(server, access_token, client_id, myproxy_server):
    """
    Trigger the nexus_server to register with the oauth_server.
    Returns: home_url, gateway_name, public_key, oauth_consumer_id
    """

    headers = { 'Content-type': 'app/json',
            'X-Globus-Goauthtoken': access_token}
    body = '{"oauth_consumer_id": "%s", "oauth_server": "%s"}' \
            % (client_id, myproxy_server)
    c = httplib.HTTPSConnection(server, 443)
    c.request('POST', '/identity_providers/oauth_registration',
            body=body, headers=headers)
    response = c.getresponse()
    json_reader = None
    if hasattr(json, 'loads'):
        json_reader = json.loads
    elif hasattr(json, 'JsonReader'):
        json_reader_obj = json.JsonReader()
        json_reader = json_reader_obj.read
    if response.status == 403:
        try:
            message = json_reader(response.read()).get('message')
        except Exception, e:
            message = str(e)
        raise Exception('403 Error: %s' % message)
    elif response.status > 299 or response.status < 200:
        raise Exception('%d Error: %s' % (response.status, response.reason))
    data = json_reader(response.read())
    home_url = data.get('home_url')
    gateway_name = data.get('gateway_name')
    oauth_consumer_id = data.get('oauth_consumer_id')
    public_key = data.get('public_key')
    return (home_url, gateway_name, oauth_consumer_id, public_key)


"""
Implementation of OAuth for MyProxy Protocol,
https://docs.google.com/document/pub?id=10SC7oSURc-EgxMQjcCS50gz0u2HzDJAFiG5hEHiSdxA
"""

@application.route('/initiate', methods=['GET'])
def initiate(environ, start_response):
    request = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ)
    oauth_signature_method = request.getvalue('oauth_signature_method')
    if oauth_signature_method is None:
        oauth_signature_method='RSA-SHA1'
    oauth_signature = str(request.getvalue('oauth_signature'))
    oauth_timestamp = int(request.getvalue('oauth_timestamp'))
    oauth_nonce = int(request.getvalue('oauth_nonce'))
    oauth_version = str(request.getvalue('oauth_version'))
    oauth_consumer_key = str(request.getvalue('oauth_consumer_key'))
    oauth_callback = str(request.getvalue('oauth_callback'))
    certlifetime = request.getvalue('certlifetime')
    if certlifetime is not None:
        certlifetime = int(certlifetime)
    else:
        certlifetime = 86400

    client = db_session.query(Client).\
            filter(Client.oauth_consumer_key==oauth_consumer_key).first()
    if client is None:
        application.logger.error('Unregistered client requested a temporary token.')
        status = "403 Not authorized"
        headers = [
                ("Content-Type", "text/plain") ]
        start_response(status, headers)
        return "Uregistered client"

    if hasattr(Crypto.PublicKey.RSA, 'importKey'):
        key = Crypto.PublicKey.RSA.importKey(client.oauth_client_pubkey)
    else:
        import M2Crypto.RSA
        import M2Crypto.BIO
        import struct
        import sys

        bio = M2Crypto.BIO.MemoryBuffer(str(client.oauth_client_pubkey))

        k = None
        try:
            k = M2Crypto.RSA.load_pub_key_bio(bio)
            def unpack_from(fmt, data, offs):
                unpack_len = struct.calcsize(fmt)

                return struct.unpack(fmt, data[offs:offs+unpack_len])

	    def decode(n):
		len = reduce(lambda x,y: long(x*256+y),
			unpack_from("4B", n, 0))
		return reduce(lambda x,y: long(x*256+y),
			unpack_from(str(len)+"B", n, 4))
	    keytuple = (decode(k.n), decode(k.e))
        except Exception, e:
            application.logger.error(str(sys.exc_info()))
            raise(e)

	key = Crypto.PublicKey.RSA.construct(keytuple)

    method = environ['REQUEST_METHOD']
    url = url_reconstruct(environ)
    o_request = oauth.Request.from_request(method, url)
    o_consumer = oauth.Consumer(client.oauth_consumer_key, key)
    o_server = oauth.Server()
    o_server.add_signature_method(oauth.SignatureMethod_RSA_SHA1())
    try:
        o_server.verify_request(o_request, o_consumer, None)
    except oauth.Error, e:
        application.logger.error(str(e))
        status = "403 Not authorized"
        headers = [
                ("Content-Type", "text/plain") ]
        start_response(status, headers, exc=e)
        return str(e)

    certreq = str(request.getvalue('certreq'))

    oauth_temp_token = 'myproxy:oa4mp,2012:/tempCred/' \
            + ''.join([random.choice('0123456789abcdef') for i in range(32)]) \
            + '/' + str(int(time.time()))
    transaction = Transaction()
    transaction.temp_token = oauth_temp_token
    transaction.temp_token_valid = 1
    transaction.oauth_callback = oauth_callback
    transaction.certreq = certreq
    transaction.oauth_consumer_key = oauth_consumer_key
    transaction.certlifetime = certlifetime
    transaction.timestamp = int(time.time())
    db_session.add(transaction)
    db_session.commit()

    status = "200 Ok"
    headers = [
	("Content-Type", "app/x-www-form-urlencoded") ]
    start_response(status, headers)

    return "oauth_token=%s&oauth_callback_confirmed=true" % oauth_temp_token

@application.route('/authorize', methods=['GET'])
def get_authorize(environ, start_response):
    request = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ)
    oauth_temp_token = str(request.getvalue('oauth_token'))
    transaction = db_session.query(Transaction).\
	    filter(Transaction.temp_token==oauth_temp_token).\
	    filter(Transaction.temp_token_valid==1).first()
    if transaction is None:
	status = "403 Not authorized"
	headers = [ ("Content-Type", "text/plain") ]
	start_response(status, headers)
	return 'Invalid temporary token'

    client = db_session.query(Client).\
	    filter(Client.oauth_consumer_key==
	    transaction.oauth_consumer_key).first()
    if client is None:
	status = "403 Not authorized"
	headers = [ ("Content-Type", "text/plain") ]
	start_response(status, headers)
	return 'Unregistered client'

    transaction.temp_token_valid = 0
    db_session.add(transaction)
    db_session.commit()
    res = render_template('authorize.html',
	    client_name=client.name,
	    client_url=client.home_url,
	    temp_token=oauth_temp_token)
    status = "200 Ok"
    headers = [ ("Content-Type", "text/html")]
    start_response(status, headers)
    return res


@application.route('/authorize', methods=['POST'])
def post_authorize(environ, start_response):
    request = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ)
    oauth_temp_token = str(request.getvalue('oauth_token'))
    username = str(request.getvalue('username'))
    passphrase = str(request.getvalue('passphrase'))

    transaction = db_session.query(Transaction).\
            filter(Transaction.temp_token==oauth_temp_token).first()
    client = db_session.query(Client).\
            filter(Client.oauth_consumer_key==transaction.oauth_consumer_key).\
            first()
    cert = None
    try:
        certreq = "-----BEGIN CERTIFICATE REQUEST-----\n" + str(transaction.certreq) + "-----END CERTIFICATE REQUEST-----\n"
        cert = myproxy.myproxy_logon(certreq,
                transaction.certlifetime,
                username, passphrase, client.myproxy_server)
    except Exception, e:
        application.logger.debug(str(e))
        status = "200 Ok"
        headers = [ ("Content-Type", "text/html") ]
        res = render_template('authorize.html',
                    client_name=client.name,
                    client_url=client.home_url,
                    temp_token=oauth_temp_token,
                    retry_message=str(e))
        start_response(status, headers, e)
        return res

    oauth_verifier = 'myproxy:oa4mp,2012:/verifier/' \
            + ''.join([random.choice('0123456789abcdef') for i in range(32)]) \
            + '/' + str(int(time.time()))

    transaction.oauth_verifier = oauth_verifier
    transaction.certificate = cert
    transaction.username = username
    db_session.add(transaction)
    db_session.commit()

    status = "301 Moved Permanently"
    headers = [
            ("Location", str("%s?oauth_token=%s&oauth_verifier=%s" % \
            (transaction.oauth_callback, oauth_temp_token, oauth_verifier)))]

    start_response(status, headers)
    return ""

@application.route('/token', methods=['GET'])
def token(environ, start_response):
    args = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ)
    oauth_signature_method = args.getvalue('oauth_signature_method')
    if oauth_signature_method is None:
       oauth_signature_method='RSA-SHA1'
    else:
       oauth_signature_method=str(oauth_signature_method)
    oauth_signature = str(args.getvalue('oauth_signature'))
    oauth_timestamp = int(args.getvalue('oauth_timestamp'))
    oauth_nonce = int(args.getvalue('oauth_nonce'))
    oauth_version = str(args.getvalue('oauth_version'))
    oauth_consumer_key = str(args.getvalue('oauth_consumer_key'))
    oauth_temp_token = str(args.getvalue('oauth_token'))
    oauth_verifier = str(args.getvalue('oauth_verifier'))

    oauth_access_token = 'myproxy:oa4mp,2012:/accessToken/' \
            + ''.join([random.choice('0123456789abcdef') for i in range(32)]) \
            + '/' + str(int(time.time()))

    transaction = db_session.query(Transaction).\
            filter(Transaction.temp_token==oauth_temp_token).first()
    transaction.access_token = oauth_access_token
    db_session.add(transaction)
    db_session.commit()

    status = "200 Ok"
    headers = [('Content-Type', 'app/x-www-form-urlencoded')]
    resp = start_response(status, headers)
    return "oauth_token=%s" % str(oauth_access_token)

@application.route('/getcert', methods=['GET'])
def getcert(environ, start_response):
    args = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ)
    oauth_signature_method = args.getvalue('oauth_signature_method')
    if oauth_signature_method is None:
       oauth_signature_method = 'RSA-SHA1'
    else:
       oauth_signature_method = str(oauth_signature_method)
    oauth_signature = str(args.getvalue('oauth_signature'))
    oauth_timestamp = int(args.getvalue('oauth_timestamp'))
    oauth_nonce = int(args.getvalue('oauth_nonce'))
    oauth_version = str(args.getvalue('oauth_version'))
    oauth_consumer_key = str(args.getvalue('oauth_consumer_key'))
    oauth_access_token = str(args.getvalue('oauth_token'))

    transaction = db_session.query(Transaction).\
            filter(Transaction.access_token==oauth_access_token).first()
    if transaction is None:
        status = "403 Forbidden"
        headers = [("Content-Type", "text/plain")]
        start_response(status, headers)
        return "Invalid access token"

    # Clear database
    old_transactions = db_session.query(Transaction).\
            filter(Transaction.timestamp < int(time.time()) - 300).delete()
    db_session.commit()

    status = "200 Ok"
    headers = [ ("Content-Type", "app/x-www-form-urlencoded") ]
    start_response(status, headers)

    return 'username=%s\n%s' % (str(transaction.username), str(transaction.certificate))
# vim: syntax=python: nospell:
