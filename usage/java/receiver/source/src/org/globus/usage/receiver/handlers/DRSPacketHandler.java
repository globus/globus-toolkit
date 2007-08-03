/*
 * Copyright 1999-2007 University of Chicago
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

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.DRSUsageMonitorPacket;
import org.globus.usage.packets.Util;
import org.globus.usage.packets.UsageMonitorPacket;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Properties;

/*Handler which writes DRSUsageMonitor packets to database.*/
public class DRSPacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(DRSPacketHandler.class);

    public DRSPacketHandler(Properties props) 
    throws SQLException {
        super(props.getProperty("database-pool"),
              props.getProperty("drs-table", "drs_packets"));
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == DRSUsageMonitorPacket.COMPONENT_CODE && 
                versionCode == DRSUsageMonitorPacket.PACKET_VERSION);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new DRSUsageMonitorPacket();
    }

    //uses DefaultPacketHandler's handlePacket().

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{
        if (!(pack instanceof DRSUsageMonitorPacket)) {
            log.error("Something is seriously wrong: DRSUsageMonitorPacket got a packet which was not a DRSUsageMonitorPacket.");
            throw new SQLException();
        }

        DRSUsageMonitorPacket drs = (DRSUsageMonitorPacket)pack;

        PreparedStatement ps;
        ps = con.prepareStatement("INSERT INTO "+table+" (component_code, version_code, send_time, ip_address, number_of_files, number_of_resources) VALUES(?, ?, ?, ?, ?, ?);");

        ps.setShort(1, drs.getComponentCode());
        ps.setShort(2, drs.getPacketVersion());
        ps.setTimestamp(3, new Timestamp(drs.getTimestamp()));
        ps.setString(4, Util.getAddressAsString(drs.getHostIP()));

        ps.setLong(5, drs.getNumberOfFiles());
        ps.setLong(6, drs.getNumberOfResources());

        return ps;
    }
}
