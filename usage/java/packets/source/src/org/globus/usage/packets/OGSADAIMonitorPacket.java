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
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Connection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.IPTimeMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;

public class OGSADAIMonitorPacket extends IPTimeMonitorPacket
{
    static Log log = LogFactory.getLog(OGSADAIMonitorPacket.class);

    private Date resourceCreationTime;
    private String currentActivity;

    private static short COMPONENT_CODE = 8;
    private static short PACKET_VERSION = 1;
    private static short MAX_CURRENT_ACTIVITY_LEN = 64;

    public OGSADAIMonitorPacket() 
    {
        setComponentCode(COMPONENT_CODE);
        setPacketVersion(PACKET_VERSION);
    }

    public Date getResourceCreationTime() 
    {
        return this.resourceCreationTime;
    }

    public void setResourceCreationTime(Date resourceCreationTime) 
    {
        this.resourceCreationTime = resourceCreationTime;
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
        buf.putLong(this.resourceCreationTime.getTime());
        
        byte[] currentActivityBytes = this.currentActivity.getBytes();
        byte[] fixedCurrentActivityBytes = new byte[MAX_CURRENT_ACTIVITY_LEN];
        for (int i = 0; i < MAX_CURRENT_ACTIVITY_LEN; i++)
        {
            if (currentActivityBytes.length > i)
            {
                fixedCurrentActivityBytes[i] = currentActivityBytes[i];
            }
        }
        buf.put(fixedCurrentActivityBytes);
    }

    public void unpackCustomFields(CustomByteBuffer buf) 
    {
        super.unpackCustomFields(buf);
        this.resourceCreationTime = new Date(buf.getLong());

        byte[] fixedCurrentActivityBytes = new byte[MAX_CURRENT_ACTIVITY_LEN];
        buf.get(fixedCurrentActivityBytes);

        // drop trailing zeros
        int i = (MAX_CURRENT_ACTIVITY_LEN - 1);
        while((fixedCurrentActivityBytes[i] == 0) && (i > 0))
        {
            i--;
        }
        this.currentActivity = new String(fixedCurrentActivityBytes, 0, i+1);
    }

    public String toString() 
    {
        return super.toString() + " Resource Creation Time: " +
            this.resourceCreationTime.getTime() + " Current Activity: " +
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
            " (component_code, version_code, send_time, ip_address, resource_creation_time, activity) VALUES(?, ?, ?, ?, ?, ?);");

	ps.setShort(1, this.getComponentCode());
	ps.setShort(2, this.getPacketVersion());
	ps.setTimestamp(3, new Timestamp(this.getTimestamp()));
        ps.setString(4, Util.getAddressAsString(getHostIP()));
	ps.setTimestamp(5, new Timestamp(this.resourceCreationTime.getTime()));
	ps.setString(6, this.currentActivity);

	return ps;
    }
} 
