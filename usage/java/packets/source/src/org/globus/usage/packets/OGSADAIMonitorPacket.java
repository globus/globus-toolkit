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
package org.globus.usage.packets;

import java.util.Date;

import java.sql.Timestamp;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.Util;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.IPTimeMonitorPacket;

public class OGSADAIMonitorPacket extends IPTimeMonitorPacket
{
    static Log log = LogFactory.getLog(OGSADAIMonitorPacket.class);

    private String currentActivity;

    private static short COMPONENT_CODE = 8;
    private static short PACKET_VERSION = 1;

    public OGSADAIMonitorPacket() 
    {
        setComponentCode(COMPONENT_CODE);
        setPacketVersion(PACKET_VERSION);
    }

    public String getCurrentActivity()
    {
        return this.currentActivity;
    }

    public void setCurrentActivity(String activity)
    {
        this.currentActivity = activity;
    }

    public void packCustomFields(CustomByteBuffer buf) 
    {
        super.packCustomFields(buf);

        long activityLen = currentActivity.length();
        buf.putLong(activityLen);

        byte[] currentActivityBytes = this.currentActivity.getBytes();
        buf.put(currentActivityBytes);
    }

    public void unpackCustomFields(CustomByteBuffer buf) 
    {
        super.unpackCustomFields(buf);

        int activityLen = new Long(buf.getLong()).intValue();

        byte[] fixedCurrentActivityBytes = new byte[activityLen];
        buf.get(fixedCurrentActivityBytes);

        this.currentActivity = new String(fixedCurrentActivityBytes);
    }

    public String toString() 
    {
        return super.toString() + " Activity: " +
            this.currentActivity;
    }

    public void debug() 
    {
        log.debug(this.toString());
    }

    public void display()
    {
        log.info(this.toString());
    }
    
    public PreparedStatement toSQL(Connection con, String tablename) throws SQLException
    {
	PreparedStatement ps;
	ps = con.prepareStatement(
            "INSERT INTO " + tablename +
            " (component_code, version_code, send_time, ip_address, activity) VALUES(?, ?, ?, ?, ?);");

	ps.setShort(1, this.getComponentCode());
	ps.setShort(2, this.getPacketVersion());
	ps.setTimestamp(3, new Timestamp(this.getTimestamp()));
        ps.setString(4, Util.getAddressAsString(getHostIP()));
	ps.setString(5, this.currentActivity);

	return ps;
    }
} 
