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
import org.globus.wsrf.container.usage.ContainerUsageBasePacketV2;
import org.globus.wsrf.container.usage.ContainerUsageStartPacketV2;
import org.globus.wsrf.container.usage.ContainerUsageStopPacketV2;

import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.util.Properties;

public class JavaCorePacketHandlerV2 extends DefaultPacketHandler {
    private static Log log = 
        LogFactory.getLog(JavaCorePacketHandlerV2.class);
    
    public JavaCorePacketHandlerV2(Properties props)
        throws SQLException {
        super(props.getProperty("database-pool"),
              props.getProperty("jws-core-table", "java_ws_core_packets"));
    }

    public String getDescription() {
        return "Java WS Core v2 packets";
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == ContainerUsageBasePacket.COMPONENT_CODE) &&
            (versionCode == ContainerUsageBasePacketV2.PACKET_VERSION);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {

	/*Look inside the rawBytes to see
	  whether to instantiate StartPacket (eventType == START_EVENT)
	  or StopPacket (eventType == STOP_EVENT).*/
	ContainerUsageBasePacket temp = new ContainerUsageBasePacket();

	temp.parseByteArray(rawBytes.array());
	rawBytes.rewind();

        short eventType = temp.getEventType();
        short version = temp.getPacketVersion();

	if (eventType == ContainerUsageStartPacket.START_EVENT) {
            return new ContainerUsageStartPacketV2();
	} else if (eventType == ContainerUsageStopPacket.STOP_EVENT) {
            return new ContainerUsageStopPacketV2();
        } 

        throw new IllegalArgumentException(
                        "Unsupported event: " + eventType);
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) 
        throws SQLException {

	PreparedStatement ps;
	ContainerUsageBasePacketV2 jPack;

        if (!(pack instanceof ContainerUsageBasePacketV2)) {
	    throw new SQLException("Can't happen.");
        }
	jPack = (ContainerUsageBasePacketV2)pack;

	ps = con.prepareStatement("INSERT INTO " + this.table + " (component_code, version_code, send_time, ip_address, container_id, container_type, event_type, service_list, optional_val) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");

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

        ps.setString(8, jPack.getServiceList());

        ps.setInt(9, jPack.getOptionalIntField());

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
	    service_list TEXT,
            optional_val INT
	  );

	  service_list is only used if event_type is 1.
	  if event_type is 2, it's stop_packet.
	 */
    }
}
