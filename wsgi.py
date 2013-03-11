import os
import sys


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

sys.path.insert(0, BASE_DIR)

from myproxyoauth import application
