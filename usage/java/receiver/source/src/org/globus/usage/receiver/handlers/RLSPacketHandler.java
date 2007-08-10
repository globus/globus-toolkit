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

import org.globus.usage.packets.RLSMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.usage.packets.Util;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Properties;

/*Handler which writes RLS packets to database.*/
public class RLSPacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(RLSPacketHandler.class);

    public RLSPacketHandler(Properties props) throws SQLException {
        super(props.getProperty("database-pool"),
              props.getProperty("rls-table", "rls_packets"));
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return ((componentCode == 7 && (versionCode == 0 || versionCode == 7)) ||
                (componentCode == 1792 && versionCode == 0)); // little endian encoding
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new RLSMonitorPacket();
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{
        if (!(pack instanceof RLSMonitorPacket)) {
            log.error("Can't happen.");
            throw new SQLException();
        }

        RLSMonitorPacket rlsPack= (RLSMonitorPacket)pack;
        
        PreparedStatement ps;
        ps = con.prepareStatement("INSERT INTO "+table+" (component_code, version_code, send_time, ip_address, rls_version, uptime, lrc, rli, lfn, pfn, mappings, rli_lfns, rli_lrcs, rli_senders, rli_mappings, threads, connections) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");

        ps.setShort(1, rlsPack.getComponentCode());
        ps.setShort(2, rlsPack.getPacketVersion());
        ps.setTimestamp(3, new Timestamp(rlsPack.getTimestamp()));
        ps.setString(4, Util.getAddressAsString(rlsPack.getHostIP()));

        ps.setString(5, rlsPack.versionString);
        ps.setLong(6, rlsPack.uptime);
        ps.setBoolean(7, rlsPack.lrc);
        ps.setBoolean(8, rlsPack.rli);
        ps.setInt(9, rlsPack.lfn);
        ps.setInt(10, rlsPack.pfn);
        ps.setInt(11, rlsPack.map);
        ps.setInt(12, rlsPack.rlilfn);
        ps.setInt(13, rlsPack.rlilrc);
        ps.setInt(14, rlsPack.rliSenders);
        ps.setInt(15, rlsPack.rliMap);
        ps.setInt(16, rlsPack.threads);
        ps.setInt(17, rlsPack.connections);

        return ps;
    }
}
