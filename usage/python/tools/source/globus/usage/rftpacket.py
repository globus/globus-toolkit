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
Object definition for processing RFT usage packets.
"""

from globus.usage.iptimemonitorpacket import IPTimeMonitorPacket

class RFTPacket(IPTimeMonitorPacket):
    """
    RFT Usage Packet handler
    """
    def __init__(self, address, packet):
        IPTimeMonitorPacket.__init__(self, address, packet)
        [ self.request_type,
            self.number_of_files,
            self.number_of_bytes,
            self.number_of_resources,
            self.resource_creation_time,
            self.factory_start_time
        ] = self.unpack("Bqqqqq")


    insert_statement = '''
            INSERT INTO rft_packets(
                component_code,
                version_code,
                send_time,
                ip_address,
                request_type,
                number_of_files,
                number_of_bytes,
                number_of_resources,
                creation_time,
                factory_start_time)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''

    def values(self, dbclass):
        """
        Return a values tuple which matches the parameters in the
        class's insert_statement.

        Arguments:
        self -- A RFTPacket object

        Returns:
        Tuple containing
            (component_code, version_code, send_time, ip_address,
             request_type, number_of_files, number_of_bytes,
             number_of_resources, creation_time,
             factory_start_time)

        """
        return (
            self.component_code,
            self.packet_version,
            dbclass.Timestamp(*self.send_time),
            self.ip_address,
            self.request_type,
            self.number_of_files,
            self.number_of_bytes,
            self.number_of_resources,
            self.resource_creation_time,
            self.factory_start_time)

