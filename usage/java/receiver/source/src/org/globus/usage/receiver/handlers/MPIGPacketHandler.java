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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.MPIGMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.usage.packets.Util;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Properties;

/*Handler which writes GramUsageMonitor packets to database.*/
public class MPIGPacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(MPIGPacketHandler.class);

    public MPIGPacketHandler(Properties props)
    throws SQLException {
        super(props.getProperty("database-pool"),
              props.getProperty("mpig-table", "mpig_packets"));
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 8 && (versionCode == 0));
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new MPIGMonitorPacket();
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{
        if (!(pack instanceof MPIGMonitorPacket)) {
            log.error("Can't happen.");
            throw new SQLException();
        }

        MPIGMonitorPacket packet = (MPIGMonitorPacket) pack;
        
        PreparedStatement ps;
        ps = con.prepareStatement("INSERT INTO "+table+" (component_code, version_code, send_time, ip_address, hostname, mpichver, start_time, end_time, nprocs, bytes_sent, vendor_bytes_sent, test, function_map) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
       
        ps.setShort(1, packet.getComponentCode());
        ps.setShort(2, packet.getPacketVersion());
        ps.setTimestamp(3, new Timestamp(packet.getTimestamp()));
        ps.setString(4, Util.getAddressAsString(packet.getHostIP()));

        ps.setString(5, packet.getHostname());
        ps.setString(6, packet.getMpichVer());
        ps.setTimestamp(7, packet.getStartTimestamp());
        ps.setTimestamp(8, packet.getEndTimestamp());
        ps.setInt(9, packet.getNprocs());
        ps.setLong(10, packet.getNbytes());
        ps.setLong(11, packet.getNbytesv());
        ps.setInt(12, packet.getTest());
        ps.setString(13, packet.getFnmap());

        return ps;
    }
}
