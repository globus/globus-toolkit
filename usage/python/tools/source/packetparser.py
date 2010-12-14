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

import struct
import socket
import sys
import os
sys.path.append(os.path.join(os.getenv("GLOBUS_LOCATION"), "lib", "python"))

import usagepacket
import gram4packet
import gridftppacket
import cwscorev1packet
import cwscorev2packet
import javawscorev1packet
import javawscorev2packet
import javawscorev3packet
import rlspacket
import mpigpacket
import rftpacket
import drspacket
import mdsaggregatorpacket
import ogsadaipacket
import myproxypacket
import gram5packet

__packet_classifier = \
{
    (0,0): gridftppacket.GridFTPPacket,
    (1,1): gram4packet.GRAM4Packet,
    (3,1): javawscorev1packet.JavaWSCoreV1Packet,
    (3,2): javawscorev2packet.JavaWSCoreV2Packet,
    (3,3): javawscorev3packet.JavaWSCoreV3Packet,
    (4,1): cwscorev1packet.CWSCoreV1Packet,
    (4,2): cwscorev2packet.CWSCoreV2Packet,
    (5,1): rftpacket.RFTPacket,
    (6,0): mdsaggregatorpacket.MDSAggregatorPacket,
    (7,0): rlspacket.RLSPacket,
    (8,0): mpigpacket.MPIGPacket,
    (9,0): drspacket.DRSPacket,
    (10,1): ogsadaipacket.OGSADAIPacket,
    (11,0): myproxypacket.MyProxyPacket,
    (20,0): gram5packet.GRAM5JMPacket,
    (20,1): gram5packet.GRAM5JobPacket
}

def parse(address, packet):
    """
    Parse the usage packet

    Arguments:
    packet -- Binary usage packet data
    """
    values = struct.unpack("!hh", packet[0:struct.calcsize("!hh")])

    constructor = __packet_classifier.get(values)

    if (constructor is None) and (
                values[0] > usagepacket.ENDIAN_CHECK or \
                values[1] > usagepacket.ENDIAN_CHECK):
        constructor = __packet_classifier.get(
            tuple(map(socket.htons, list(values))))

    if constructor is None:
        print "Unknown packet type " + str(values)
        constructor = usagepacket.UsagePacket

    return constructor(address, packet)
