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
import org.globus.wsrf.container.usage.ContainerUsagePacketV3;

import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.util.Properties;

public class JavaCorePacketHandlerV3 extends DefaultPacketHandler {
    private static Log log = 
        LogFactory.getLog(JavaCorePacketHandlerV3.class);
    
    public JavaCorePacketHandlerV3(Properties props) throws SQLException {
        super(props.getProperty("database-pool"),
              props.getProperty("jws-core-table", "java_ws_core_packets"));
    }

    public String getDescription() {
        return "Java WS Core v3 packets";
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == ContainerUsagePacketV3.COMPONENT_CODE) &&
            (versionCode == ContainerUsagePacketV3.PACKET_VERSION);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {

	/*Look inside the rawBytes to see what type of event to pass to
         packet constructor */
	ContainerUsageBasePacket temp = new ContainerUsageBasePacket();

	temp.parseByteArray(rawBytes.array());
	rawBytes.rewind();

        short eventType = temp.getEventType();
        return new ContainerUsagePacketV3(eventType);
    }
   

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) 
        throws SQLException 
    {
        PreparedStatement ps;
        ContainerUsagePacketV3 jPack;
        
        if (!(pack instanceof ContainerUsagePacketV3)) {
	    throw new SQLException("Can't happen.");
        }
        jPack = (ContainerUsagePacketV3)pack;
        
        ps = con.prepareStatement("INSERT INTO " + this.table + " (component_code, version_code, send_time, ip_address, container_id, container_type, event_type, service_list, optional_val, version_major, version_minor, version_micro, port_number, thread_pool_size, thread_count, max_threads, threads_high_water_mark, service_request_count, jvm_info) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

        ps.setShort(1, jPack.getComponentCode());
        ps.setShort(2, jPack.getPacketVersion());
        ps.setTimestamp(3, new Timestamp(jPack.getTimestamp()));
        if (jPack.getHostIP() == null) {
            ps.setString(4, "unknown");
        } else {
            ps.setString(4, jPack.getHostIP().toString());
        }
        ps.setInt(5, jPack.getContainerID());
        ps.setShort(6, jPack.getContainerType());
        ps.setShort(7, jPack.getEventType());
        ps.setString(8, jPack.getServiceList());
        ps.setInt(9, jPack.getUptime());
        ps.setShort(10, jPack.getMajorVersion());
        ps.setShort(11, jPack.getMinorVersion());
        ps.setShort(12, jPack.getMicroVersion());
        ps.setInt(13, jPack.getPortNumber());
        ps.setShort(14, jPack.getThreadPoolSize());
        ps.setShort(15, jPack.getCurrentThreadCount());
        ps.setShort(16, jPack.getMaxThreadCount());
        ps.setShort(17, jPack.getThreadsHighWaterMark());	
        ps.setInt(18, jPack.getServiceRequestCount());        
        // only write the JVM info to the DB for startup events
        if (jPack.getEventType() == ContainerUsagePacketV3.START_EVENT) {
            ps.setString(19, jPack.getJvmInfo());
        } else {
            ps.setString(19, "");
        }        
        return ps;
        /*

            CREATE TABLE java_ws_core_packets(
                id SERIAL,
                component_code SMALLINT NOT NULL,
                version_code SMALLINT NOT NULL,
                send_time TIMESTAMP,
                ip_address VARCHAR(64) NOT NULL,
                container_id INT,
                container_type SMALLINT,
                event_type SMALLINT,
                service_list TEXT,
                optional_val INT,
                version_major SMALLINT,
                version_minor SMALLINT,
                version_micro SMALLINT,
                port_number INT,
                thread_pool_size SMALLINT,
                thread_count SMALLINT,
                max_threads SMALLINT,
                threads_high_water_mark SMALLINT,
                service_request_count INT,
                jvm_info VARCHAR(64)
            );
	 */
    }
}
