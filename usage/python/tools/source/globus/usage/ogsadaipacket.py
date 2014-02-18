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
Object definition for processing OGSADAI usage packets.
"""

from globus.usage.iptimemonitorpacket import IPTimeMonitorPacket

class OGSADAIPacket(IPTimeMonitorPacket):
    """
    OGSADAI Usage Packet
    """

    def __init__(self, address, packet):
        IPTimeMonitorPacket.__init__(self, address, packet)
        [activity_len] = self.unpack("q")
        self.activity = self.unpack_string(activity_len)

    insert_statement = '''
        INSERT INTO ogsadai_packets (
            component_code,
            version_code,
            send_time,
            ip_address,
            activity)
        VALUES (%s, %s, %s, %s, %s)
    '''

    def values(self, dbclass):
        """
        Return a values tuple which matches the parameters in the
        class's insert_statement.

        Arguments:
        self -- An OGSADAIPacket object

        Returns:
        Tuple containing
            (component_code, version_code, send_time, ip_address, activity)

        """
        return (
            self.component_code,
            self.packet_version,
            dbclass.Timestamp(*self.send_time),
            self.ip_address,
            self.activity)
