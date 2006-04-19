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
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Date;
import java.util.Calendar;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class RLSMonitorPacket extends CStylePacket {

    private String versionString;
    private long uptime; //number of seconds
    private boolean lrc;
    private boolean rli;
    private int lfn;
    private int pfn;
    private int map;
    private int rlilfn;
    private int rlilrc;
    private int rliSenders;
    private int rliMap;
    private int threads;
    private int connections;

    /*Code is 7, version is 0*/

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

    public PreparedStatement toSQL(Connection con, String tablename) throws SQLException {
	PreparedStatement ps;
	ps = con.prepareStatement("INSERT INTO "+tablename+" (component_code, version_code, send_time, ip_address, rls_version, uptime, lrc, rli, lfn, pfn, mappings, rli_lfns, rli_lrcs, rli_senders, rli_mappings, threads, connections) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
	
	ps.setShort(1, this.getComponentCode());
	ps.setShort(2, this.getPacketVersion());
	ps.setTimestamp(3, new Timestamp(this.getTimestamp()));
	ps.setString(4, Util.getAddressAsString(getHostIP()));

	ps.setString(5, this.versionString);
	ps.setLong(6, this.uptime);
	ps.setBoolean(7, this.lrc);
	ps.setBoolean(8, this.rli);
	ps.setInt(9, this.lfn);
	ps.setInt(10, this.pfn);
	ps.setInt(11, this.map);
	ps.setInt(12, this.rlilfn);
	ps.setInt(13, this.rlilrc);
	ps.setInt(14, this.rliSenders);
	ps.setInt(15, this.rliMap);
	ps.setInt(16, this.threads);
	ps.setInt(17, this.connections);
	return ps;
    }

}
