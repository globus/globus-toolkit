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

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.MDSAggregatorMonitorPacket;
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.usage.packets.Util;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Properties;

public class MDSAggregatorPacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(MDSAggregatorPacketHandler.class);

    public MDSAggregatorPacketHandler(Properties props) throws SQLException {
        super(props.getProperty("database-pool"),
              props.getProperty("mds-table", "mds_packets"));
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 6 && versionCode == 0);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new MDSAggregatorMonitorPacket();
    }
   
    protected PreparedStatement makeSQLInsert(UsageMonitorPacket packet) throws SQLException{
        if (!(packet instanceof MDSAggregatorMonitorPacket)) {
            log.error("Invalid Packet Type: expected MDSAggregatorMonitorPacket");
            throw new SQLException();
        }

        MDSAggregatorMonitorPacket mds = (MDSAggregatorMonitorPacket)packet;

	PreparedStatement ps;
	ps = con.prepareStatement("INSERT INTO "+table+" (component_code, version_code, send_time, ip_address, service_name, lifetime_reg_count, current_reg_count, resource_creation_time) VALUES(?, ?, ?, ?, ?, ?, ?, ?);");

	ps.setShort(1, mds.getComponentCode());
	ps.setShort(2, mds.getPacketVersion());
	ps.setTimestamp(3, new Timestamp(mds.getTimestamp()));
	ps.setString(4, Util.getAddressAsString(mds.getHostIP()));

        ps.setString(5, mds.getServiceName());
	ps.setLong(6, mds.getLifetimeRegistrationCount());
        ps.setLong(7, mds.getCurrentRegistrantCount());
	ps.setTimestamp(8, new Timestamp(mds.getResourceCreationTime().getTime()));

	return ps;
    }
}
