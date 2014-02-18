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
Core Usage packet parser and uploader
"""
import struct
import socket

ENDIAN_CHECK = 24

class UsagePacket(object):
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
        New UsagePacket

        """
        if len(address) == 4:
            self.ip_address = socket.inet_ntop(
                    socket.AF_INET, address)
        elif len(address) == 16:
            self.ip_address = socket.inet_ntop(
                    socket.AF_INET6, address)
        else:
            self.ip_address = None
        checkvals = struct.unpack("!hh", packet[0:struct.calcsize("!hh")])
        self.endian_prefix = "!"
        if (checkvals[0] > ENDIAN_CHECK) or \
                (checkvals[1] > ENDIAN_CHECK):
            self.endian_prefix = "<"
        packdata = struct.unpack(
                self.endian_prefix + "hh", 
			packet[0:struct.calcsize(self.endian_prefix + "hh")])
        offset = struct.calcsize(self.endian_prefix + "hh")
        self.component_code = packdata[0]
        self.packet_version = packdata[1]
        self.packet_body = packet
        self.packet_body_offset = offset

    insert_statement = '''
                INSERT INTO unknown_packets(
                    componentcode, versioncode, contents)
                VALUES(%s, %s, %s)'''

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


    def upload(self, cursor):
        """
        Upload this packet to the database.

        Arguments:
        self -- A usagepacket.usagepacket object
        cursor -- An SQL cursor to use if we need to insert this packet into
        the table.

        Returns:
        None.

        """
        cursor.execute(self.insert_statement, self.values())

    @staticmethod
    def upload_many(dbclass, cursor, packets):
        """
        Upload multiple usage packets of the same type. Returns an array
        of packets which could not be uploaded
        """
        values = map(lambda x: x.values(dbclass), packets)

        # Ideally, we'd just upload the whole block of packets at once;
        # however, sometimes we get an invalid packet that violates some
        # database constraint. I'm not sure we can get the point where the 
        # insert failed from the cursor (poor doc), so we'll instead roll back
        # to our savepoint and try to upload half of the packets, continuing
        # halfwise until we hit the bad packet. When we find the bad packet,
        # we'll store it in bad_packets and then try to upload everything
        # after the bad packet.
        #
        # The bad packets are returned so the caller can do something about
        # reporting them
        start = 0
        end = len(values)
        blocksize = len(values)
        bad_packets = []

        while start < end:
            cursor.execute("SAVEPOINT uploadmany")
            try:
                cursor.executemany(
                        packets[0].insert_statement,
                        values[start:start+blocksize])
                cursor.execute("RELEASE SAVEPOINT uploadmany")
                start = start + blocksize
                blocksize = end - start
            except:
                cursor.execute("ROLLBACK TO SAVEPOINT uploadmany")
                if blocksize > 1:
                    # If insert fails, roll back to save point, then
                    # attempt to upload half of the values
                    blocksize = blocksize / 2
                else:
                    # If insert fails with a block size of 1, then 
                    # we've found a bad packet, so we'll drop it and continue
                    # with the rest of the packets
                    if packets[start] is not None:
                        bad_packets.append(packets[start])
                    start = start + 1
                    blocksize = end - start
        return bad_packets

    @staticmethod
    def upload_aggregation(dbclass, cursor):
        pass

    @staticmethod
    def parse_address(address):
        """
        Parse an address in the binary usage packet's sender address format.
        The address is a 16 byte array. If bytes 0-12 are \0, then assume
        it's an IPv4 address, otherwise, an IPv6 address.

        Arguments:
        self -- A usagepacket.usagepacket object
        address -- Address array

        Returns:
        None.

        """
        ipv6 = 0
        for i in range(12):
            if address[i] != 0:
                ipv6 = 1
                break
        if ipv6 == 1:
            return socket.inet_ntop(
                socket.AF_INET6, struct.pack('!16B', *address))
        else:
            return socket.inet_ntop(
                socket.AF_INET,
                struct.pack('!BBBB', *address[12:]))

    def unpack(self, format):
        """
        Unpack the next data from the usage packet body. Accepts the format
        strings handled by struct.unpack, minus the leading endian indicator,
        which is determined by the packet header.

        Arguments:
        self -- the packet to unpack
        format -- a struct.unpack() style format string

        Return:
        The unpacked data

        Side Effects:
        Alters the self.packet_body_offset to point after the current format
        was parsed

        """
        endian_qualified_format = self.endian_prefix + format
        fmtsize = struct.calcsize(endian_qualified_format)
        endpack = self.packet_body_offset + fmtsize
        res = struct.unpack(
                endian_qualified_format,
                self.packet_body[self.packet_body_offset:endpack])
        self.packet_body_offset = endpack
        return res
