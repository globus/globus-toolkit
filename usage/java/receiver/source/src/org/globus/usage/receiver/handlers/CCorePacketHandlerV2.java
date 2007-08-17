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

import org.globus.usage.packets.CWSMonitorPacketV2;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.usage.packets.Util;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Properties;

public class CCorePacketHandlerV2 extends DefaultPacketHandler {
    private static Log log = LogFactory.getLog(CCorePacketHandlerV2.class);

    public CCorePacketHandlerV2(Properties props) throws SQLException {
        super(props.getProperty("database-pool"),
              props.getProperty("cws-core-table", "c_ws_core_packets"));
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
	if (log.isDebugEnabled()) {
		log.debug("Checking to see if (component, version) = (" + 
		componentCode + ", " + versionCode + ") is handled");
	}

        return (componentCode == 4 && versionCode == 2);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new CWSMonitorPacketV2();
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack)
            throws SQLException
    {
        if (!(pack instanceof CWSMonitorPacketV2)) {
            log.error("Can't happen.");
            throw new SQLException();
        }

        CWSMonitorPacketV2 cPack = (CWSMonitorPacketV2)pack;

	PreparedStatement ps;
	ps = con.prepareStatement("INSERT INTO "+table+" (component_code, version_code, send_time, ip_address, container_id, event_type, service_list) VALUES (?, ?, ?, ?, ?, ?, ?);");

	
        log.debug("SQLing");
	ps.setShort(1, cPack.getComponentCode());
	ps.setShort(2, cPack.getPacketVersion());
	ps.setTimestamp(3, new Timestamp(cPack.getTimestamp()));
	ps.setString(4, Util.getAddressAsString(cPack.getHostIP()));
        ps.setInt(5, cPack.getId());
        ps.setInt(6, cPack.getEvent());
        ps.setString(7, cPack.getServices());

	return ps;
    }
}
