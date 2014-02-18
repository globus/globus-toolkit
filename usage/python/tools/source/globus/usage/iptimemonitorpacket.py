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
Core Usage packet parser for java sourced packets based on the IPTimeMonitor
packet

"""
import struct
import time
import socket
from globus.usage.usagepacket import UsagePacket

class IPTimeMonitorPacket(UsagePacket):
    """
    Base usage packet parser and handler
    """
    def __init__(self, address, packet):
        """
        Initialize a usagepacket from a binary string containing the UDP
        packet contents.

        Arguments:
        self -- The new usagepacket.usagepacket object
        packet -- The binary packet contents

        Returns:
        New IPTimeMonitorPacket

        """
        UsagePacket.__init__(self, address, packet)
        packdata = self.unpack("qB")
        time_sent_millis = packdata[0]
        time_sent = time_sent_millis / 1000
        frac_secs = time_sent_millis - int(time_sent_millis)
        send_time = list(time.gmtime(time_sent))[0:6]
        send_time[5] += frac_secs
        self.send_time = tuple(send_time)
        address_form = packdata[1]
        if address_form == 4:
            address_data = self.unpack("4B")
            self.ip_address = socket.inet_ntop(
                            socket.AF_INET, struct.pack('4B', *address_data))
        elif address_form == 6:
            address_data = self.unpack("16B")
            self.ip_address = socket.inet_ntop(
                            socket.AF_INET6, struct.pack('16B', *address_data))

    insert_statement = '''
                INSERT INTO unknown_packets(
                    componentcode, versioncode, contents)
                VALUES(%s, %s, %s)'''

    def unpack_string(self, string_len):
        if (string_len + self.packet_body_offset) > len(self.packet_body):
            string_len = len(self.packet_body) - self.packet_body_offset
        string_data = list(self.unpack("%dB" % string_len))
        string_data.append(0)
        string_data = string_data[0:string_data.index(0)]
        return struct.pack("%dB" % len(string_data), *string_data)

    def values(self, dbclass):
        """
        Return a values tuple which matches the parameters in the
        class's insert_statement.

        Arguments:
        self -- A UsagePacket object

        Returns:
        Tuple containing
            (componentcode, versioncode, contents)

        """
        
        return  (
            self.component_code,
            self.packet_version,
            dbclass.Binary(self.packet_body))

    def __str__(self):
        res  = "Component Code: " + str(self.component_code) + "\n"
        res += "Packet Version: " + str(self.packet_version) + "\n"
        res += "Sender Address: " + str(self.ip_address) + "\n"
        res += "Time Sent: " + str(self.send_time) + "\n"
        if self.__class__ == UsagePacket:
            res += "Packet Body: " + str(self.packet_body) + "\n"
        else:
            res += "Other type" + "\n"
        return res
