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

public class RLSMonitorPacket extends CStylePacket {
    public static final short COMPONENT_CODE = 7;
    public static final short PACKET_VERSION = 0;
    public String versionString;
    public long uptime; //number of seconds
    public boolean lrc;
    public boolean rli;
    public int lfn;
    public int pfn;
    public int map;
    public int rlilfn;
    public int rlilrc;
    public int rliSenders;
    public int rliMap;
    public int threads;
    public int connections;

    public void RLSMonitorPacket() {
        setComponentCode(COMPONENT_CODE);
        setPacketVersion(PACKET_VERSION);
    }

    public void unpackCustomFields(CustomByteBuffer buf) {
	super.unpackCustomFields(buf);
	PacketFieldParser parser = parseTextSection(buf);

	try {
		senderAddress = InetAddress.getByName(parser.getString("HOSTNAME"));
        } catch (UnknownHostException uhe) {}
	
	this.versionString = parser.getString("VER");
	this.uptime = parser.getLong("UPTIME");
	this.lrc = (parser.getInt("LRC") == 1);
	this.rli = (parser.getInt("RLI") == 1);
	this.lfn = parser.getInt("LFN");
	this.pfn = parser.getInt("PFN");
	this.map = parser.getInt("MAP");
	this.rlilfn = parser.getInt("RLILFN");
	this.rlilrc = parser.getInt("RLILRC");
	this.rliSenders = parser.getInt("RLISND");
	this.rliMap = parser.getInt("RLIMAP");
	this.threads = parser.getInt("THRD");
	this.connections = parser.getInt("CONN");
    }
}
