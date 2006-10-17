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

import java.util.Date;

import java.sql.Timestamp;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Connection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.IPTimeMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;

public class MDSExtendedMonitorPacket 
       extends IPTimeMonitorPacket 
{
    static Log log = LogFactory.getLog(MDSExtendedMonitorPacket.class);

    private long numSuccessfulQueries;
    private long numFailedQueries;
    private long numTotalQueries;
    private Date resourceCreationTime;
    private Date lastUpdateStartTime;
    private String serviceName;

    private static short COMPONENT_CODE = 7;
    private static short PACKET_VERSION = 0;
    private static short MAX_SERVICE_NAME_LEN = 40;

    public MDSExtendedMonitorPacket() 
    {
        setComponentCode(COMPONENT_CODE);
        setPacketVersion(PACKET_VERSION);       
    }

    public long getNumSuccessfulQueries() 
    {
        return this.numSuccessfulQueries;
    }

    public void setNumSuccessfulQueries(long numSuccessfulQueries) 
    {
        this.numSuccessfulQueries = numSuccessfulQueries;
    }

    public long getNumFailedQueries() 
    {
        return this.numFailedQueries;
    }

    public void setNumFailedQueries(long numFailedQueries) 
    {
        this.numFailedQueries = numFailedQueries;
    }

    public long getNumTotalQueries() 
    {
        return this.numTotalQueries;
    }

    public void setNumTotalQueries(long numTotalQueries) 
    {
        this.numTotalQueries = numTotalQueries;
    }

    public Date getResourceCreationTime() 
    {
        return this.resourceCreationTime;
    }

    public void setResourceCreationTime(Date resourceCreationTime) 
    {
        this.resourceCreationTime = resourceCreationTime;
    }

    public Date getLastUpdateStartTime()
    {
        return this.lastUpdateStartTime;
    }

    public void setLastUpdateStartTime(Date lastUpdateStartTime)
    {
        this.lastUpdateStartTime = lastUpdateStartTime;
    }

    public void setServiceName(String serviceName)
    {
        this.serviceName = serviceName;
    }

    public String getServiceName()
    {
        return this.serviceName;
    }

    public void packCustomFields(CustomByteBuffer buf) 
    {
        super.packCustomFields(buf);

        byte[] serviceNameBytes = this.serviceName.getBytes();
        byte[] fixedServiceNameBytes = new byte[MAX_SERVICE_NAME_LEN];        
        for (int i = 0; i < MAX_SERVICE_NAME_LEN; i++)
        {
            if (serviceNameBytes.length > i)
            {
                fixedServiceNameBytes[i] = serviceNameBytes[i];
            }
        }
        buf.put(fixedServiceNameBytes);

        buf.putLong(this.getNumSuccessfulQueries());
        buf.putLong(this.getNumFailedQueries());
        buf.putLong(this.getNumTotalQueries());
        buf.putLong(this.resourceCreationTime.getTime());
        buf.putLong(this.lastUpdateStartTime.getTime());
    }

    public void unpackCustomFields(CustomByteBuffer buf) 
    {
        super.unpackCustomFields(buf);

        byte[] fixedServiceNameBytes = new byte[MAX_SERVICE_NAME_LEN];
	buf.get(fixedServiceNameBytes);

        int i = MAX_SERVICE_NAME_LEN - 1;
        while(fixedServiceNameBytes[i] == 0 && i > 0)
        {
            i--;
        }

	this.serviceName = new String(fixedServiceNameBytes, 0, i+1);

        this.numSuccessfulQueries = buf.getLong();
        this.numFailedQueries = buf.getLong();
        this.numTotalQueries = buf.getLong();
        this.resourceCreationTime = new Date(buf.getLong());
        this.lastUpdateStartTime = new Date(buf.getLong());
    }

    public String toString()
    {
        return super.toString() +
            " Service Name: " + this.serviceName +
            " numSuccessfulQueries : " + this.numSuccessfulQueries +
            " numFailedQueries : " + this.numFailedQueries +
            " numTotalQueries : " + this.numTotalQueries +
            " Resource Creation Time: " + this.resourceCreationTime +
            " Time Since Last Update: " + this.lastUpdateStartTime;
    }

    public void debug() 
    {
        log.debug(this.toString());
    }

    public void display() {
        log.info(this.toString());
    }

    public PreparedStatement toSQL(Connection con, String tablename) throws SQLException
    {
	PreparedStatement ps;
	ps = con.prepareStatement("INSERT INTO "+tablename+" (component_code, version_code, send_time, ip_address, service_name, successful_queries, failed_queries, total_queries, resource_creation_time, last_update_time) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");

	ps.setShort(1, this.getComponentCode());
	ps.setShort(2, this.getPacketVersion());
	ps.setTimestamp(3, new Timestamp(this.getTimestamp()));
	ps.setString(4, Util.getAddressAsString(getHostIP()));

        ps.setString(5, this.serviceName);
	ps.setLong(6, this.numSuccessfulQueries);
        ps.setLong(7, this.numFailedQueries);
	ps.setLong(8, this.numTotalQueries);
	ps.setTimestamp(9, new Timestamp(this.resourceCreationTime.getTime()));
	ps.setTimestamp(10, new Timestamp(this.lastUpdateStartTime.getTime()));

	return ps;
    }
}
