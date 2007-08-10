/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.globus.usage.packets;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CWSMonitorPacket extends CStylePacket {
    public static final short COMPONENT_CODE = 4;
    public static final short PACKET_VERSION = 1;

    public CWSMonitorPacket() {
        super();
        this.componentCode = COMPONENT_CODE;
        this.packetVersion = PACKET_VERSION;
    }

    public void unpackCustomFields(CustomByteBuffer buf) {
	super.unpackCustomFields(buf);
	PacketFieldParser parser = parseTextSection(buf);
	try {
	    this.senderAddress = InetAddress.getByName(parser.getString("HOSTNAME"));
	} catch (UnknownHostException uhe) {}
    }
}
