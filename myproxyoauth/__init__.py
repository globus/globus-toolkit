from myproxyoauth.database import init_db

init_db()

import logging, sys
logging.basicConfig(stream=sys.stderr)

from flask import Flask

application = Flask(__name__)

application.config['DATABASE'] = 'sqlite:///tmp/myproxy-oauth.db'

import myproxyoauth.views
