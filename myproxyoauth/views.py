import socket
import random
import base64
import httplib
import json
import time
import oauth2 as oauth
from Crypto.PublicKey import RSA
import myproxy
from flask import request, render_template, make_response, redirect
from myproxyoauth import application
from myproxyoauth.database import db_session, Admin, Client, Transaction

'''
@application.errorhandler(404)
def not_found(error):
    return 'Error 404 :)'
'''
@application.route('/test')
def test():
    return make_response('blad :)', 403)


@application.teardown_request
def shutdown_session(exception=None):
    db_session.remove()


"""
Register Globus Online OAuth with the server. The registration consists of two
steps:
1. Get an OAuth access token from Globus Online.
2. Trigger a Globus Online client registration with the service.
"""

@application.route('/configure', methods=['GET', 'POST'])
def configure():
    if request.method == 'GET':
        name = socket.gethostname()
        if name.find('.') ==  -1:
            name = socket.gethostbyaddr(name)[0]
        return render_template('configure.html', hostname=name)

    username = request.form['username'].encode('utf-8')
    password = request.form['password'].encode('utf-8')
    oauth_server = request.form['oauth_server'].encode('utf-8')
    myproxy_server = request.form['myproxy_server'].encode('utf-8')
    nexus_server = request.form['nexus_server'].encode('utf-8')
    application.logger.debug('Configure: username: %s, oauth_server: %s,'
            ' myproxy_server: %s, nexus_server: %s' %
            (username, oauth_server, myproxy_server, nexus_server))

    admin = db_session.query(Admin).first()

    if admin is not None:
        if admin.username != username:
            application.logger.warning('Configure: %s is trying to register GO'
                    ' with this MyProxy Delegation Service' % username)
            return render_template('configure_error.html',
                    message='You are not an admin of the MyProxy Delegation Service')

    try:
        access_token = get_access_token(username, password, nexus_server)
    except Exception as e:
        return render_template('configure_error.html', message
                = 'Could not get access token. %s' % str(e))

    client_id = 'myproxy:oa4mp,2012:/client/' \
        + ''.join([random.choice('0123456789abcdef') for i in range(32)])
    try:
        (home_url, gateway_name, oauth_consumer_id, public_key) = register_go(
                nexus_server, access_token, client_id, oauth_server)
    except Exception as e:
        return render_template('configure_error.html', message=str(e))

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

    return render_template('configure_ok.html', gateway_name=gateway_name,
            home_url=home_url, oauth_consumer_id=oauth_consumer_id,
            public_key=public_key)


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
    if response.status == 403:
        try :
            message = json.loads(response.read()).get('message')
        except Exception as e:
            message = str(e)
        raise Exception('403 Error: %s' % message)
    elif response.status > 299 or response.status < 200:
        raise Exception('%d Error: %s' % (response.status, response.reason))
    data = json.loads(response.read())
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
    if response.status == 403:
        try:
            message = json.loads(response.read()).get('message')
        except Exception as e:
            message = str(e)
        raise Exception('403 Error: %s' % message)
    elif response.status > 299 or response.status < 200:
        raise Exception('%d Error: %s' % (response.status, response.reason))
    data = json.loads(response.read())
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
def initiate():
    oauth_signature_method = request.args.get('oauth_signature_method',
            default='RSA-SHA1', type=str)
    oauth_signature = request.args.get('oauth_signature', type=str)
    oauth_timestamp = request.args.get('oauth_timestamp', type=int)
    oauth_nonce = request.args.get('oauth_nonce', type=int)
    oauth_version = request.args.get('oauth_version', type=str)
    oauth_consumer_key = request.args.get('oauth_consumer_key', type=str)
    oauth_callback = request.args.get('oauth_callback', type=str)
    certlifetime = request.args.get('certlifetime', default=86400, type=int)


    client = db_session.query(Client).\
            filter(Client.oauth_consumer_key==oauth_consumer_key).first()
    if client is None:
        application.logger.error('Unregistered client requested a temporary token.')
        return make_response('Uregistered client', 403)

    key = RSA.importKey(client.oauth_client_pubkey)

    o_request = oauth.Request.from_request(request.method, request.url)
    o_consumer = oauth.Consumer(client.oauth_consumer_key, key)
    o_server = oauth.Server()
    o_server.add_signature_method(oauth.SignatureMethod_RSA_SHA1())
    try:
        o_server.verify_request(o_request, o_consumer, None)
    except oauth.Error as e:
        application.logger.error(str(e))
        return make_response(str(e), 403)

    certreq = request.args.get('certreq', type=str)
    certreq = "-----BEGIN CERTIFICATE REQUEST-----\n" + certreq \
            + "-----END CERTIFICATE REQUEST-----"

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

    resp = make_response("oauth_token=%s&oauth_callback_confirmed=true"
            % oauth_temp_token)
    resp.headers['Content-Type'] = 'app/x-www-form-urlencoded'
    return resp


@application.route('/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'GET':
        oauth_temp_token = request.args.get('oauth_token', type=str)
        transaction = db_session.query(Transaction).\
                filter(Transaction.temp_token==oauth_temp_token).\
                filter(Transaction.temp_token_valid==1).first()
        if transaction is None:
            return make_response('Invalid temporary token', 403)
        client = db_session.query(Client).\
                filter(Client.oauth_consumer_key==
                transaction.oauth_consumer_key).first()
        if client is None:
            return make_response('Unregistered client', 403)
        transaction.temp_token_valid = 0
        db_session.add(transaction)
        db_session.commit()
        return render_template('authorize.html',
                client_name=client.name,
                client_url=client.home_url,
                temp_token=oauth_temp_token)

    oauth_temp_token = request.form['oauth_token']
    username = request.form['username']
    passphrase = request.form['passphrase']

    transaction = db_session.query(Transaction).\
            filter(Transaction.temp_token==oauth_temp_token).first()
    client = db_session.query(Client).\
            filter(Client.oauth_consumer_key==transaction.oauth_consumer_key).\
            first()
    cert = None
    try:
        cert = myproxy.myproxy_logon(transaction.certreq, transaction.certlifetime,
                username, passphrase, client.myproxy_server)
    except Exception as e:
            return render_template('authorize.html',
                    client_name=client.name,
                    client_url=client.home_url,
                    temp_token=oauth_temp_token,
                    retry_message=str(e))

    oauth_verifier = 'myproxy:oa4mp,2012:/verifier/' \
            + ''.join([random.choice('0123456789abcdef') for i in range(32)]) \
            + '/' + str(int(time.time()))

    transaction.oauth_verifier = oauth_verifier
    transaction.certificate = cert
    transaction.username = username
    db_session.add(transaction)
    db_session.commit()

    resp = redirect("%s?oauth_token=%s&oauth_verifier=%s" % \
            (transaction.oauth_callback, oauth_temp_token, oauth_verifier))
    return resp


@application.route('/token', methods=['GET'])
def token():
    oauth_signature_method = request.args.get('oauth_signature_method', default='RSA-SHA1', type=str)
    oauth_signature = request.args.get('oauth_signature', type=str)
    oauth_timestamp = request.args.get('oauth_timestamp', type=int)
    oauth_nonce = request.args.get('oauth_nonce', type=int)
    oauth_version = request.args.get('oauth_version', type=str)
    oauth_consumer_key = request.args.get('oauth_consumer_key', type=str)
    oauth_temp_token = request.args.get('oauth_token', type=str)
    oauth_verifier = request.args.get('oauth_verifier', type=str)

    oauth_access_token = 'myproxy:oa4mp,2012:/accessToken/' \
            + ''.join([random.choice('0123456789abcdef') for i in range(32)]) \
            + '/' + str(int(time.time()))

    transaction = db_session.query(Transaction).\
            filter(Transaction.temp_token==oauth_temp_token).first()
    transaction.access_token = oauth_access_token
    db_session.add(transaction)
    db_session.commit()

    resp = make_response("oauth_token=%s" % oauth_access_token)
    resp.headers['Content-Type'] = 'app/x-www-form-urlencoded'
    return resp


@application.route('/getcert', methods=['GET'])
def getcert():
    oauth_signature_method = request.args.get('oauth_signature_method', default='RSA-SHA1', type=str)
    oauth_signature = request.args.get('oauth_signature', type=str)
    oauth_timestamp = request.args.get('oauth_timestamp', type=int)
    oauth_nonce = request.args.get('oauth_nonce', type=int)
    oauth_version = request.args.get('oauth_version', type=str)
    oauth_consumer_key = request.args.get('oauth_consumer_key', type=str)
    oauth_access_token = request.args.get('oauth_token', type=str)

    transaction = db_session.query(Transaction).\
            filter(Transaction.access_token==oauth_access_token).first()
    if transaction is None:
        return make_response('Invalid access token', 403)

    # Clear database
    old_transactions = db_session.query(Transaction).\
            filter(Transaction.timestamp < int(time.time()) - 300).delete()
    db_session.commit()

    return 'username=%s\n%s' % (transaction.username, transaction.certificate)
