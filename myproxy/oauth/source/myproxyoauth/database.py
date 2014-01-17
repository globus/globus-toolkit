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

try:
    import sqlite3
except:
    from pysqlite2 import dbapi2 as sqlite3

class Admin(object):
    def __init__(self, username=None):
        self.username = username

class Client(object):
    def __init__(self, oauth_consumer_key=None, oauth_client_pubkey=None, name=None, home_url=None, myproxy_server=None, limited_proxy=0):
        self.oauth_consumer_key = oauth_consumer_key
        self.oauth_client_pubkey = oauth_client_pubkey
        self.name = name
        self.home_url = home_url
        self.myproxy_server = myproxy_server
        self.limited_proxy = limited_proxy

class Transaction(object):
    def __init__(self, temp_token=None, temp_token_valid=None,
            oauth_callback=None, certreq=None, oauth_consumer_key=None,
            oauth_verifier=None, access_token=None, access_token_valid=None,
            certificate=None, username=None, certlifetime=None, timestamp=None):
        self.temp_token = temp_token
        self.temp_token_valid = temp_token_valid
        self.oauth_callback = oauth_callback
        self.certreq = certreq
        self.oauth_consumer_key = oauth_consumer_key
        self.oauth_verifier = oauth_verifier
        self.access_token = access_token
        self.access_token_valid = access_token_valid
        self.certificate = certificate
        self.username = username
        self.certlifetime = certlifetime
        self.timestamp = timestamp

class Database(object):
    def __init__(self, path='/var/lib/myproxy-oauth/myproxy-oauth.db'):
        self.connection = sqlite3.connect(path)
        self.cursor = self.connection.cursor()

    def init_db(self):
        table_exists_query = """
            SELECT name
            FROM sqlite_master WHERE type='table' AND name=?"""
        self.cursor.execute(table_exists_query, ['admin'])
        if len(self.cursor.fetchall()) == 0:
            self.cursor.execute("CREATE TABLE admin(username TEXT PRIMARY KEY)")

        self.cursor.execute(table_exists_query, ['clients'])
        if len(self.cursor.fetchall()) == 0:
            self.cursor.execute("""
                CREATE TABLE clients (
                oauth_consumer_key TEXT PRIMARY KEY,
                oauth_client_pubkey TEXT,
                name TEXT,
                home_url TEXT,
                myproxy_server TEXT,
                limited_proxy INTEGER DEFAULT 0
                );""")
        self.cursor.execute(table_exists_query, ['transactions'])
        if len(self.cursor.fetchall()) == 0:
            self.cursor.execute("""
                CREATE TABLE transactions(
                    temp_token TEXT PRIMARY KEY,
                    temp_token_valid INTEGER,
                    oauth_callback TEXT,
                    certreq TEXT,
                    oauth_consumer_key TEXT,
                    oauth_verifier TEXT UNIQUE,
                    access_token TEXT UNIQUE,
                    access_token_valid INTEGER,
                    certificate TEXT,
                    username TEXT,
                    certlifetime INTEGER,
                    timestamp INTEGER
                );""")

    def commit(self):
        self.connection.commit()

    def add_admin(self, admin):
        self.cursor.execute("INSERT INTO admin(username) VALUES(?)",
            [admin.username])

    def get_admin(self, admin=None):
        query = "SELECT username FROM admin"
        wheres = []
        args = []

        if admin is not None:
            if admin.username is not None:
                wheres.append("username = ?")
                args.append(admin.username)

        if len(wheres) > 0:
            query = query + " WHERE " + " AND ".join(wheres)

        self.cursor.execute(query, args)
        res = []
        for row in self.cursor:
            res.append(Admin(*row))

        return res

    def add_client(self, client):
        self.cursor.execute("""
            INSERT INTO clients(
                oauth_consumer_key, oauth_client_pubkey, name,
                home_url, myproxy_server, limited_proxy)
            VALUES(?,?,?,?,?,?)""", [
                client.oauth_consumer_key, client.oauth_client_pubkey,
                client.name, client.home_url, client.myproxy_server,
                client.limited_proxy])

    def get_client(self, client=None):
        query = """
                SELECT oauth_consumer_key, oauth_client_pubkey, name,
                        home_url, myproxy_server, limited_proxy
                FROM clients
                """
        wheres = []
        args = []

        if client is not None:
            if client.oauth_consumer_key is not None:
                wheres.append("oauth_consumer_key = ?")
                args.append(client.oauth_consumer_key)
            if client.oauth_client_pubkey is not None:
                wheres.append("oauth_client_pubkey = ?")
                args.append(client.oauth_client_pubkey)
            if client.name is not None:
                wheres.append("name = ?")
                args.append(client.name)
            if client.home_url is not None:
                wheres.append("home_url = ?")
                args.append(client.home_url)
            if client.myproxy_server is not None:
                wheres.append("myproxy_server = ?")
                args.append(client.myproxy_server)
            if client.limited_proxy is not None:
                wheres.append("limited_proxy = ?")
                args.append(client.limited_proxy)

        if len(wheres) > 0:
            query = query + "WHERE " + " AND ".join(wheres)

        self.cursor.execute(query, args)
        res = []
        for row in self.cursor:
            res.append(Client(*row))
            
        return res

    def delete_clients(self, clients):
        if len(clients) > 0:
            self.cursor.executemany(
                "DELETE FROM clients WHERE oauth_consumer_key = ?",
                [(tuple([c.oauth_consumer_key])) for c in clients])

    def add_transaction(self, transaction):
        self.cursor.execute("""
            INSERT INTO transactions (temp_token, temp_token_valid,
                oauth_callback, certreq, oauth_consumer_key,
                oauth_verifier, access_token, access_token_valid,
                certificate, username, certlifetime, timestamp)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [transaction.temp_token,
                transaction.temp_token_valid, transaction.oauth_callback,
                transaction.certreq, transaction.oauth_consumer_key,
                transaction.oauth_verifier, transaction.access_token,
                transaction.access_token_valid, transaction.certificate,
                transaction.username, transaction.certlifetime,
                transaction.timestamp])

    def update_transaction(self, transaction):
        query = "UPDATE transactions SET "
        sets = []
        args = []
        if transaction.temp_token_valid is not None:
            sets.append("temp_token_valid = ?")
            args.append(transaction.temp_token_valid)
        if transaction.oauth_callback is not None:
            sets.append("oauth_callback = ?")
            args.append(transaction.oauth_callback)
        if transaction.certreq is not None:
            sets.append("certreq = ?")
            args.append(transaction.certreq)
        if transaction.oauth_consumer_key is not None:
            sets.append("oauth_consumer_key = ?")
            args.append(transaction.oauth_consumer_key)
        if transaction.oauth_verifier is not None:
            sets.append("oauth_verifier = ?")
            args.append(transaction.oauth_verifier)
        if transaction.access_token is not None:
            sets.append("access_token = ?")
            args.append(transaction.access_token)
        if transaction.access_token_valid is not None:
            sets.append("access_token_valid = ?")
            args.append(transaction.access_token_valid)
        if transaction.certificate is not None:
            sets.append("certificate = ?")
            args.append(transaction.certificate)
        if transaction.username is not None:
            sets.append("username = ?")
            args.append(transaction.username)
        if transaction.certlifetime is not None:
            sets.append("certlifetime = ?")
            args.append(transaction.certlifetime)
        if transaction.timestamp is not None:
            sets.append("timestamp = ?")
            args.append(transaction.timestamp)
        query = query + ",".join(sets) + " WHERE temp_token=?"
        args.append(transaction.temp_token)
        self.cursor.execute(query, args)
        
    def delete_transactions(self, transactions):
        if len(transactions) > 0:
            self.cursor.executemany(
                "DELETE FROM transactions WHERE temp_token = ?",
                [(t.temp_token,) for t in transactions])

    def get_transaction(self, transaction=None):
        query = """
                SELECT
                    temp_token, temp_token_valid,
                    oauth_callback, certreq, oauth_consumer_key,
                    oauth_verifier, access_token, access_token_valid,
                    certificate, username, certlifetime, timestamp
                FROM transactions"""
        wheres = []
        args = []

        if transaction is not None:
            if transaction.temp_token is not None:
                wheres.append("temp_token = ?")
                args.append(transaction.temp_token)
            if transaction.temp_token_valid is not None:
                wheres.append("temp_token_valid = ?")
                args.append(transaction.temp_token_valid)
            if transaction.oauth_callback is not None:
                wheres.append("oauth_callback = ?")
                args.append(transaction.oauth_callback)
            if transaction.certreq is not None:
                wheres.append("certreq = ?")
                args.append(transaction.certreq)
            if transaction.oauth_consumer_key is not None:
                wheres.append("oauth_consumer_key = ?")
                args.append(transaction.oauth_consumer_key)
            if transaction.oauth_verifier is not None:
                wheres.append("oauth_verifier = ?")
                args.append(transaction.oauth_verifier)
            if transaction.access_token is not None:
                wheres.append("access_token = ?")
                args.append(transaction.access_token)
            if transaction.access_token_valid is not None:
                wheres.append("access_token_valid = ?")
                args.append(transaction.access_token_valid)
            if transaction.certificate is not None:
                wheres.append("certificate = ?")
                args.append(transaction.certificate)
            if transaction.username is not None:
                wheres.append("username = ?")
                args.append(transaction.username)
            if transaction.certlifetime is not None:
                wheres.append("certlifetime = ?")
                args.append(transaction.certlifetime)
            if transaction.timestamp is not None:
                wheres.append("timestamp = ?")
                args.append(transaction.timestamp)

        if len(wheres) > 0:
            query = query + " WHERE " + " AND ".join(wheres)

        self.cursor.execute(query, args)
        res = []
        for row in self.cursor:
            res.append(Transaction(*row))
        return res

db_session = Database()
init_db = db_session.init_db
