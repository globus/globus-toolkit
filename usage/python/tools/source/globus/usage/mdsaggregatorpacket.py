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
Object definition for processing MDS aggregator usage packets.
"""

from globus.usage.iptimemonitorpacket import IPTimeMonitorPacket

class MDSAggregatorPacket(IPTimeMonitorPacket):
    """
    MDS Aggregator Usage Packet

    """

    __MAX_SERVICE_NAME_LEN = 40
    def __init__(self, address, packet):
        IPTimeMonitorPacket.__init__(self, address, packet)
        self.service_name = self.unpack_string(
                MDSAggregatorPacket.__MAX_SERVICE_NAME_LEN)
        (
            self.lifetime_registration_count,
            self.current_registrant_count,
            self.resource_creation_time
        ) = self.unpack("qqq")

    insert_statement = '''
            INSERT INTO mds_packets(
                component_code,
                version_code,
                send_time,
                ip_address,
                service_name,
                lifetime_reg_count,
                current_reg_count,
                resource_creation_time)
            VALUES(%s, %s, %s, %s, %s, %s,%s, %s)
            '''

    def values(self, dbclass):
        """
        Return a values tuple which matches the parameters in the class's
        insert_statement.

        Arguments:
        self -- A MDSAggregatorPacket object
        dbclass -- Database driver module for driver-specific type bindings

        Returns:
        Tuple containing
            (component_code, version_code, send_time, ip_address,
             service_name, lifetime_reg_count, current_reg_count,
             resource_creation_time)

        """

        return (
            self.component_code,
            self.packet_version,
            dbclass.Timestamp(*self.send_time),
            self.ip_address,
            self.service_name,
            str(self.lifetime_registration_count),
            str(self.current_registrant_count),
            dbclass.TimestampFromTicks(self.resource_creation_time / 1000))
