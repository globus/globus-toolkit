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
Object definition for processing C WS Core (version 2) usage packets.
"""

from globus.usage.cusagepacket import CUsagePacket

class CWSCoreV1Packet(CUsagePacket):
    """
    C WS Core Usage Packet v1.
    """
    insert_statement = """
        INSERT INTO c_ws_core_packets (
            component_code,
            version_code,
            send_time,
            ip_address)
        VALUES(%s, %s, %s, %s)"""

    def values(self, dbclass):
        """
        Return a values tuple which matches the parameters in the
        class's insert_statement.

        Arguments:
        self -- A CWSCoreV1Packet object

        Returns:
        Tuple containing
            (component_code, version_code, send_time, ip_address)

        """
        return (
            self.component_code,
            self.packet_version,
            dbclass.Timestamp(*self.send_time),
            self.ip_address)
