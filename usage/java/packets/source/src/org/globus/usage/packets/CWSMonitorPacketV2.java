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
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Date;
import java.util.Calendar;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CWSMonitorPacketV2 extends CStylePacket {
    static Log log = LogFactory.getLog(CWSMonitorPacketV2.class);

    static public final short COMPONENT_CODE = 4;
    static public final short PACKET_VERSION = 2;

    static public int START_EVENT = 1;
    static public int STOP_EVENT = 2;
    private Integer id;
    private Integer event;
    private String services;

    public CWSMonitorPacketV2() {
        super();
        this.componentCode = COMPONENT_CODE;
        this.packetVersion = PACKET_VERSION;
    }

    public int getId() {
        return id.intValue();
    }

    public void setId(int id) {
        this.id = new Integer(id);
    }

    public int getEvent() {
        return event.intValue();
    }

    public void setEvent(int event) {
        this.event = new Integer(event);
    }

    public String getServices() {
        return services;
    }

    public void setServices(String services) {
        this.services = services;
    }

    public void unpackCustomFields(CustomByteBuffer buf) {
	super.unpackCustomFields(buf);
	PacketFieldParser parser = parseTextSection(buf);

        try
        {
            this.senderAddress = InetAddress.getByName(parser.getString("HOSTNAME"));
        }
        catch (UnknownHostException uhe)
        {
        }

        log.debug("Parsing fields");

        id = parser.getInt("ID");
        log.debug("ID = " + id.toString());
        event = parser.getInt("EVENT");
        log.debug("EVENT = " + event.toString());
        services = parser.getString("SERVICES");
        log.debug("SERVICES = " + event.toString());
    }

    public PreparedStatement toSQL(Connection con, String tablename) throws SQLException {
	PreparedStatement ps;
	ps = con.prepareStatement("INSERT INTO "+tablename+" (component_code, version_code, send_time, ip_address, container_id, event_type, service_list) VALUES (?, ?, ?, ?, ?, ?, ?);");

	
        log.debug("SQLing");
	ps.setShort(1, this.getComponentCode());
	ps.setShort(2, this.getPacketVersion());
	ps.setTimestamp(3, new Timestamp(this.getTimestamp()));
	ps.setString(4, Util.getAddressAsString(getHostIP()));
        ps.setInt(5, id);
        ps.setInt(6, event);
        ps.setString(7, services);

	return ps;
    }
}
