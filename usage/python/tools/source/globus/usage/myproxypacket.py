# Copyright 1999-2009 Board of Trustees of University of Illinois
#
# Based on rlspackets.py:
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
Object definition for processing MyProxy usage packets.
"""

from globus.usage.cusagepacket import CUsagePacket

class MyProxyPacket(CUsagePacket):
    """
    MyProxy Usage Packet
    """

    insert_statement = '''
        INSERT INTO myproxy_packets (
            component_code,
            version_code,
            send_time,
            ip_address,
            hostname,
            myproxy_major_version,
            myproxy_minor_version,
            task_code,
            task_return_code,
            req_lifetime,
            cred_lifetime,
            info_bits,
            client_ip,
            user_name,
            user_dn)
        VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    '''

    def values(self, dbclass):
        """
        Return a values tuple which matches the parameters in the
        class's insert_statement.

        Arguments:
        self -- A MyProxyPacket object

        Returns:
        Tuple containing
            (component_code, version_code, send_time, ip_address,
             hostname, myproxy_major_version, myproxy_minor_version, task_code,
             task_return_code, req_lifetime, cred_lifetime, info_bits, client_ip,
             user_name, user_dn)

        """
        return (
            self.component_code,
            self.packet_version,
            dbclass.Timestamp(*self.send_time),
            self.ip_address,
            self.data.get('HOSTNAME'),
            self.data.get('MAJOR_VER'),
            self.data.get('MINOR_VER'),
            self.data.get('TASK'),
            self.data.get('RET'),
            self.data.get('REQ_LTIME'),
            self.data.get('CRED_LTIME'),
            self.data.get('BITS'),
            self.data.get('CLIENTIP'),
            self.data.get('USER'),
            self.data.get('USERDN'))
