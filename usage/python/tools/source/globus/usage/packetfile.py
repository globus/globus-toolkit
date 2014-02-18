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
Packet File I/O Class Definition
"""

import time
import struct
import os

class PacketFile(object):
    """
    Packet file parser
    
    Reads the binary packet data and returns it
    """

    def __init__(self, path = None, mode = "r"):
        self.path = path
        self.packet_file = None
        self.dstamp = None
        self.hstamp = None
        self.mode = mode
        if path is not None and mode == "r":
            self.packet_file = open(path, mode)

    def read_packet(self):
        """
        Parse the next usage packet from the packet file

        Arguments:
        self -- PacketFile object opened for reading
        
        Returns:
        A tuple containing (sender_address, binary_packet_data)
        or None if end of file is reached.
        """
        if self.mode != "r":
            return None

        lens = self.packet_file.read(2)
        if lens == '':
            return None
        if len(lens) < 2:
            raise EOFError("Error reading sender address length")
        [sender_len] = struct.unpack("!h", lens)
        sender = self.packet_file.read(sender_len)
        if sender == '' or len(sender) < sender_len:
            raise EOFError("Error reading sender address")

        lens = self.packet_file.read(2)
        if lens == '' or len(lens) < 2:
            raise EOFError("Error reading packet length")
        packet_len = 0
        [packet_len] = struct.unpack("!h", lens)
        if packet_len > 0:
            packet = self.packet_file.read(packet_len)
            if len(packet) < packet_len:
                raise EOFError("Error reading packet")

            return (sender, packet)
        else:
            return (sender, None)

    def write_packet(self, sender, packet):
        """
        Write the given packet to the appropriate packet file

        Arguments:
        self -- PacketFile object opened for writing
        packet -- Binary data containing the packet value

        Return:
        None

        """
        if self.mode != "a" and self.mode != "w":
            return None

        gmt = time.gmtime()
        dstamp = "%(year)04d%(mon)02d%(day)02d" % \
            {
                'year': gmt.tm_year,
                'mon': gmt.tm_mon,
                'day': gmt.tm_mday
            }
        hstamp = "%(hour)02d" % { 'hour': gmt.tm_hour }

        if (dstamp != self.dstamp) or (hstamp != self.hstamp):
            if self.packet_file is not None:
                self.packet_file.close()
                self.packet_file = None
            else:
                self.dstamp = dstamp
                self.hstamp = hstamp

        if self.packet_file is None:
            if not os.path.exists(os.path.join(self.path, dstamp)):
                os.makedirs(os.path.join(self.path, dstamp), 0755)
            self.packet_file = open(
                os.path.join(self.path, dstamp, hstamp + ".gup"), "a")

        self.packet_file.write(struct.pack("!h", len(sender)))
        self.packet_file.write(sender)
        self.packet_file.write(struct.pack("!h", len(packet)))
        self.packet_file.write(packet)

    def close(self):
        """
        Close the currently opened file

        Arguments:
        self -- PacketFile object opened for writing

        Return:
        None
        """
        if self.mode != "a" and self.mode != "w":
            return None
        elif self.packet_file is not None:
            self.packet_file.close()
            self.packet_file = None
