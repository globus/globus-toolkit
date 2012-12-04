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
Object definition for processing MPIG usage packets.
"""

from globus.usage.cusagepacket import CUsagePacket

class MPIGPacket(CUsagePacket):
    """
    MPIG Usage Packet
    """

    insert_statement = '''
        INSERT INTO mpig_packets (
            component_code,
            version_code,
            send_time,
            ip_address,
            hostname,
            mpichver,
            start_time,
            end_time,
            nprocs,
            bytes_sent,
            vendor_bytes_sent,
            test,
            function_map)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    '''

    def values(self, dbclass):
        """
        Return a values tuple which matches the parameters in the
        class's insert_statement.

        Arguments:
        self -- An RLSPacket object

        Returns:
        Tuple containing
            (component_code, version_code, send_time, ip_address,
            hostname, mpichver, start_time, end_time,
            nprocs, bytes_sent, vendor_bytes_sent, test, function_map)

        """
        return (
            self.component_code,
            self.packet_version,
            dbclass.Timestamp(*self.send_time),
            self.ip_address,
            self.data.get('HOSTNAME'),
            self.data.get('MPICHVER'),
            self.get_timestamp_from_attribute('START', dbclass),
            self.get_timestamp_from_attribute('END', dbclass),
            self.data.get('NPROCS'),
            self.data.get('NBYTES'),
            self.data.get('NBYTESV'),
            self.data.get('TEST'),
            self.data.get('FNMAP'))

    def get_timestamp_from_attribute(self, attribute, dbclass):
        timestamp_string = self.data.get(attribute)
        if timestamp_string is not None:
            return dbclass.TimestampFromTicks(float(timestamp_string))
        else:
            return None
