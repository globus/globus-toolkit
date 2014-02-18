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
C-Style (name=value) Usage Packet
"""

import re
import time
from globus.usage.usagepacket import UsagePacket

class CUsagePacket(UsagePacket):
    """C-Style (name=value) Usage Packet

       This packet class extends the usagepacket class to include a parser
       for NAME=VALUE and NAME="QUOTED VALUE" strings. It does not provide any
       class-specific database upload function.
    """
    _parse_re = re.compile(
        " *([^ =\\\\\\\"\r\n]+)=" +
        "((\\\"((\\\\\"|\\\\\\\\|[^\"\\\\])*)\\\")|([^\\\" ]*))")

    def __init__(self, address, packet):
        UsagePacket.__init__(self, address, packet)
        self.data = {}

        # Old version of the C usage code would call htons() twice on
        # the component code and packet version fields, but not the other
        # binary fields in the packet, so we force it to be network byte order
        # for the rest of the parsing
        self.endian_prefix = "!"
        header_data = self.unpack("16Bl")

        send_time_data = header_data[16]

        # The C Usage Packet sender sent corrupt IP addresses in the packets
        # by sending integers as octets. We'll ignore this address and use
        # the one in the udp header
        # ip_data = header_data[0:16]
        # self.ip_address = UsagePacket.parse_address(ip_data)
        self.send_time = tuple((list(time.gmtime(send_time_data)))[0:6])
        self.send_time_ticks = send_time_data

        body_str = self.packet_body[self.packet_body_offset:]

        while 1:
            match = CUsagePacket._parse_re.match(body_str)
            if match != None:
                var = match.group(1)
                if match.group(4) != None:
                    val = match.group(4)
                else:
                    val = match.group(2)
                self.data[var] = val
                body_str = body_str[match.end():]
            else:
                break

    def __str__(self):
        string = UsagePacket.__str__(self)
        for keystr in self.data.keys():
            string += keystr + ": " + self.data[keystr] + "\n"
        return string
