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
import os

import globus.usage.usagepacket as usagepacket
import globus.usage.gram4packet
import globus.usage.gridftppacket
import globus.usage.cwscorev1packet
import globus.usage.cwscorev2packet
import globus.usage.javawscorev1packet
import globus.usage.javawscorev2packet
import globus.usage.javawscorev3packet
import globus.usage.rlspacket
import globus.usage.mpigpacket
import globus.usage.rftpacket
import globus.usage.drspacket
import globus.usage.mdsaggregatorpacket
import globus.usage.ogsadaipacket
import globus.usage.myproxypacket
import globus.usage.gram5packet

__packet_classifier = \
{
    (0,0): globus.usage.gridftppacket.GridFTPPacket,
    (1,1): globus.usage.gram4packet.GRAM4Packet,
    (3,1): globus.usage.javawscorev1packet.JavaWSCoreV1Packet,
    (3,2): globus.usage.javawscorev2packet.JavaWSCoreV2Packet,
    (3,3): globus.usage.javawscorev3packet.JavaWSCoreV3Packet,
    (4,1): globus.usage.cwscorev1packet.CWSCoreV1Packet,
    (4,2): globus.usage.cwscorev2packet.CWSCoreV2Packet,
    (5,1): globus.usage.rftpacket.RFTPacket,
    (6,0): globus.usage.mdsaggregatorpacket.MDSAggregatorPacket,
    (7,0): globus.usage.rlspacket.RLSPacket,
    (8,0): globus.usage.mpigpacket.MPIGPacket,
    (9,0): globus.usage.drspacket.DRSPacket,
    (10,1): globus.usage.ogsadaipacket.OGSADAIPacket,
    (11,0): globus.usage.myproxypacket.MyProxyPacket,
    (12,0): globus.usage.gsisshpacket.GsiSshPacket,
    (20,0): globus.usage.gram5packet.GRAM5JMPacket,
    (20,1): globus.usage.gram5packet.GRAM5JobPacket
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

def packet_classes():
    return [(__packet_classifier[p]) for p in __packet_classifier]
