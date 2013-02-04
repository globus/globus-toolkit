#!/usr/bin/python

import sys
import socket
import urllib

url = 'http://169.254.169.254/latest/meta-data/%s/' % sys.argv[1]
try:
    socket.setdefaulttimeout(3.0)
    value = urllib.urlopen(url).read()
except IOError:
    sys.exit(1)
if value is None:
    sys.exit(2)
if "404 - Not Found" in value:
    sys.exit(3)
sys.stdout.write(value)
