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
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.wsrf.container.usage.ContainerUsageBasePacket;
import org.globus.wsrf.container.usage.ContainerUsageStartPacket;
import org.globus.wsrf.container.usage.ContainerUsageStopPacket;


import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.Timestamp;


/*Handler which writes GridFTPPackets to database.*/
public class JavaCorePacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(JavaCorePacketHandler.class);
    private static final short START_EVENT = 1;
    private static final short STOP_EVENT = 2;


    public JavaCorePacketHandler(String db, String table) throws SQLException {
        super(db, table);
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 3) &&
	    (versionCode == 1);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {

	/*Look inside the rawBytes to see
	  whether to instantiate StartPacket (eventType == START_EVENT)
	  or StopPacket (eventType == STOP_EVENT).*/
	ContainerUsageBasePacket temp = new ContainerUsageBasePacket();

	temp.parseByteArray(rawBytes.array());
	rawBytes.rewind();
	if (temp.getEventType() == START_EVENT) {
	    return new ContainerUsageStartPacket();
	}
	else {
	    return new ContainerUsageStopPacket();
	}
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{

	PreparedStatement ps;
	ContainerUsageBasePacket jPack;

        if (!(pack instanceof ContainerUsageBasePacket)) {
	    throw new SQLException("Can't happen.");
        }
	jPack = (ContainerUsageBasePacket)pack;

	ps = con.prepareStatement("INSERT INTO " + this.table + " (component_code, version_code, send_time, ip_address, container_id, container_type, event_type, service_list) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");

	ps.setShort(1, jPack.getComponentCode());
	ps.setShort(2, jPack.getPacketVersion());
	ps.setTimestamp(3, new Timestamp(jPack.getTimestamp()));
	if (jPack.getHostIP() == null) {
	    ps.setString(4, "unknown");
	}
	else {
	    ps.setString(4, jPack.getHostIP().toString());
	}

	ps.setInt(5, jPack.getContainerID());
	ps.setShort(6, jPack.getContainerType());
	ps.setShort(7, jPack.getEventType());

	if (pack instanceof ContainerUsageStartPacket) {
	    ContainerUsageStartPacket startPack = (ContainerUsageStartPacket)pack;
	    ps.setString(8, startPack.getServiceList());
	} else {
	    ps.setString(8, "");
	}

	return ps;
        /*

	  CREATE TABLE java_ws_core_packets(
	    id SERIAL,
	    component_code SMALLINT NOT NULL,
	    version_code SMALLINT NOT NULL,
	    send_time DATETIME,
	    ip_address VARCHAR(64) NOT NULL,
	    container_id INT,
	    container_type SMALLINT,
	    event_type SMALLINT,
	    service_list TEXT
	  );

	  service_list is only used if event_type is 1.
	  if event_type is 2, it's stop_packet.
	 */
    }
}
