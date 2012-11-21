# Copyright 1999-2009 University of Chicago
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

"""
Utilities and objects for processing the DNS cache table.
"""

import socket

class DNSCache(object):
    """
    DNS Cache
    """

    __dns_cache = dict()
    __dns_lookups = dict()
    
    def __init__(self, cursor):
        self.cursor = cursor

        cursor.execute("SELECT id, ip_address, hostname FROM dns_cache")
        for row in cursor:
            [dns_id, ip_address, hostname] = row
            DNSCache.__dns_lookups[ip_address] = hostname
            DNSCache.__dns_cache[(ip_address, hostname)] = dns_id

    def get_host_id(self, ip_address, hostname = None):
        """
        Determine the host key which matches the hostname string.
        If this hostname is not defined in the cache,
        attempt to insert it into the dns_cache table and return its new id.

        Arguments:
        self -- A DNSCache object
        ip_address -- The address to cache
        hostname -- The name to cache

        Returns:
        An integer key to the dns_cache table or None if the version is
        not defined or can't be parsed. As a side effect, this
        key may be newly defined and cached.

        """
        host_id = None
        hostnames = []
        if hostname is None and ip_address is not None:
            hostname = DNSCache.__dns_lookups.get(ip_address)
            if hostname is None:
                try:
                    hostnames = socket.gethostbyaddr(ip_address)
                except socket.herror:
                    hostnames.append('UNKNOWN')
                if hostnames is not None:
                    hostname = hostnames[0]

        if hostname is not None:
            host_ip = ip_address
            host_id = DNSCache.__dns_cache.get((host_ip, hostname))
            if host_id is None:
                domain = None
                components = hostname.rsplit(".", 1)
                if len(components) > 1:
                    domain = components[1]
                values = (host_ip, hostname, domain)
                self.cursor.execute('''
                    INSERT INTO dns_cache(
                        ip_address,
                        hostname,
                        domain)
                    VALUES(%s, %s, %s)
                    ''', values)
                self.cursor.execute('''
                    SELECT id
                    FROM dns_cache
                    WHERE ip_address = %s AND hostname = %s''', 
                    (host_ip, hostname,))
                host_id = self.cursor.fetchone()[0]
                DNSCache.__dns_cache[(host_ip, hostname)] = host_id
        return host_id

# vim: ts=4:sw=4:syntax=python
