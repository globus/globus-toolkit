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
Object definition for processing RLS usage packets.
"""

from globus.usage.cusagepacket import CUsagePacket

class RLSPacket(CUsagePacket):
    """
    RLS Usage Packet
    """

    insert_statement = '''
        INSERT INTO rls_packets (
            component_code,
            version_code,
            send_time,
            ip_address,
            rls_version,
            uptime,
            lrc,
            rli,
            lfn,
            pfn,
            mappings,
            rli_lfns,
            rli_lrcs,
            rli_senders,
            rli_mappings,
            threads,
            connections)
        VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s)
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
             rls_version, uptime, lrc, rli, lfn, pfn, mappings,
             rli_lfns, rli_lrcs, rli_senders, rli_mappings, threads,
             connections)

        """
        return (
            self.component_code,
            self.packet_version,
            dbclass.Timestamp(*self.send_time),
            self.ip_address,
            self.data.get('VER'),
            self.data.get('UPTIME'),
            self.data.get('LRC'),
            self.data.get('RLI'),
            self.data.get('LFN'),
            self.data.get('PFN'),
            self.data.get('MAP'),
            self.data.get('RLILFN'),
            self.data.get('RLILRC'),
            self.data.get('RLISND'),
            self.data.get('RLIMAP'),
            self.data.get('THRD'),
            self.data.get('CONN'))
