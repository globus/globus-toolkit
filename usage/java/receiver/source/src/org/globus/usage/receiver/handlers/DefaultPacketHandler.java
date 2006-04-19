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

package org.globus.usage.receiver.handlers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.PreparedStatement;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.usage.receiver.HandlerThread;

public class DefaultPacketHandler implements PacketHandler {
    /*The handler that will be called when receiver gets an unknown code...
      because doCodesMatch always returns true, it handles anything. It
      will just write the packet to a database as a BLOB.*/

    private static Log log = LogFactory.getLog(DefaultPacketHandler.class);

    protected String dburl;
    protected String table;
    protected Connection con;

    /* Get a connection from the pool only when we need it, in handlePacket,
       to avoid monopolizing the connections.*/
    protected long packetCount;
    protected long lostCount;

    /*Gets a database connection from the pool created by the HandlerThread.
     table is the name of the table in that database to write packets to.*/
    public DefaultPacketHandler(String dburl, String table) throws SQLException {
	//        this.dburl = dburl;
        this.table = table;
    }

    public void finalize() {
	if( con != null ) {
	    try { con.close(  ); }                
	    catch( Exception e ) { }
	}
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return true;
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new UsageMonitorPacket();
    }
   
    public void resetCounts() {
	this.packetCount = 0;
        this.lostCount = 0;
    }

    public String getStatus() {
	StringBuffer output = new StringBuffer();
	output.append(this.packetCount);
	output.append(" ");
	output.append(table);
	output.append(" logged.");
        if (this.lostCount > 0) {
            output.append(" Lost ");
            output.append(this.lostCount);
            output.append(" packets.");
        }
	return output.toString();
    }
 
    public void handlePacket(UsageMonitorPacket pack) {
        PreparedStatement stmt = null;

	this.packetCount++;

        try {
	    con = DriverManager.getConnection(HandlerThread.dbPoolName);

            if (log.isDebugEnabled()) {
                log.debug("Will write this packet to database table "
                          + table + ": ");
                log.debug(pack.toString());
            }
	    
	    stmt = makeSQLInsert(pack);
	    stmt.executeUpdate();
        } catch(SQLException e) {
            this.lostCount++;
            log.error(e.getMessage());
            log.error(pack.toString());
            String packetData = getPacketContentsBinary(pack);
	    log.error("Packet contents:");
            log.error(packetData);
        } finally {
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException e) {}
            }
            if (con != null) {
                try {
                    con.close();
                } catch (SQLException e) {}
            }
        }
    }

    protected String getPacketContentsBinary(UsageMonitorPacket pack) {
	byte[] binary = pack.getBinaryContents();
	StringBuffer output = new StringBuffer();
	for (int q = 0; q < binary.length; q++) {
	    output.append(Byte.toString(binary[q]));
            output.append(", ");
	}
        return output.toString();
    }

    /*If you want to write a handler that writes packets into a database,
      subclass DefaultPacketHandler and just override makeSQLInsert to
      return the right SQL statement..*/
    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{
	/*For better performance, save this statement and reuse it.*/
	PreparedStatement ps = con.prepareStatement("INSERT INTO "+ table +  " (componentcode, versioncode, contents) VALUES(?, ?, ?);");
           
	ps.setShort(1, pack.getComponentCode());
	ps.setShort(2, pack.getPacketVersion());
	ps.setBytes(3, pack.getBinaryContents());

	return ps;
    }
}
