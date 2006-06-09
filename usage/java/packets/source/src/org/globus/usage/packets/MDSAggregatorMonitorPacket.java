/*
 * Portions of this file Copyright 1999-2005 University of Chicago 
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the 
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without 
 * modifications, you must include this notice in the file.
 */
package org.globus.usage.packets;

import java.util.Date;
import java.util.List;

import java.net.Inet6Address;
import java.sql.Timestamp;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Connection;

import commonj.timers.Timer;
import commonj.timers.TimerListener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.IPTimeMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;

import org.globus.wsrf.container.UsageConfig;
import org.globus.wsrf.impl.timer.TimerManagerImpl;

public class MDSAggregatorMonitorPacket 
       extends IPTimeMonitorPacket 
{
    static Log log = LogFactory.getLog(MDSAggregatorMonitorPacket.class);

    private List usageTargets;
    private long lifetimeRegistrationCount;
    private long currentRegistrantCount;
    private Date resourceCreationTime;
    private String serviceName;
      
    // what is the MDS component code? FIXME
    private static short COMPONENT_CODE = 9;  
    private static short PACKET_VERSION = 0;
    private static short MAX_SERVICE_NAME_LEN = 40; // too big/small?
    
    public MDSAggregatorMonitorPacket() 
    {
        setComponentCode(COMPONENT_CODE);
        setPacketVersion(PACKET_VERSION);       
    }

    public long getLifetimeRegistrationCount() 
    {
        return this.lifetimeRegistrationCount;
    }
    
    public void setLifetimeRegistrationCount(long lifetimeRegistrationCount) 
    {
        this.lifetimeRegistrationCount = lifetimeRegistrationCount;
    }
    
    public long getCurrentRegistrantCountt() 
    {
        return this.currentRegistrantCount;
    }
    
    public void setCurrentRegistrantCount(long currentRegistrantCount) 
    {
        this.currentRegistrantCount = currentRegistrantCount;
    }
    
    public Date getResourceCreationTime() 
    {
        return this.resourceCreationTime;
    }
    
    public void setResourceCreationTime(Date resourceCreationTime) 
    {
        this.resourceCreationTime = resourceCreationTime;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }
    
    public String getServiceName() {
        return this.serviceName;
    }
    
    public void packCustomFields(CustomByteBuffer buf) 
    {
        super.packCustomFields(buf);
        
        byte[] serviceNameBytes = this.serviceName.getBytes();
        byte[] fixedServiceNameBytes = new byte[MAX_SERVICE_NAME_LEN];        
        for (int i=0; i< MAX_SERVICE_NAME_LEN; i++) {
            if (serviceNameBytes.length > i)
                fixedServiceNameBytes[i] = serviceNameBytes[i];
        }
        buf.put(fixedServiceNameBytes);
        
        buf.putLong(this.lifetimeRegistrationCount);
        buf.putLong(this.currentRegistrantCount);
        buf.putLong(this.resourceCreationTime.getTime());
    }

    public void unpackCustomFields(CustomByteBuffer buf) 
    {
        super.unpackCustomFields(buf);
        
        byte[] fixedServiceNameBytes = new byte[MAX_SERVICE_NAME_LEN];
	buf.get(fixedServiceNameBytes);
	this.serviceName = new String(fixedServiceNameBytes);
        
        this.lifetimeRegistrationCount = buf.getLong();
        this.currentRegistrantCount = buf.getLong();
        this.resourceCreationTime = new Date(buf.getLong());
    }   
    
    public String toString() 
    {
        return super.toString() +
        "Service Name: " + this.serviceName + 
        "Total Lifetime Registrations : " + this.lifetimeRegistrationCount +
        "Current Registrant Count : " + this.currentRegistrantCount +
        "Resource Creation Time: " + this.resourceCreationTime;
    }
    
    public void debug() 
    {
        log.debug(this.toString());
    }
    
    public void display() {
        log.info(this.toString());
    }
    
    public PreparedStatement toSQL(Connection con, String tablename) throws SQLException{

	PreparedStatement ps;
	ps = con.prepareStatement("INSERT INTO "+tablename+" (component_code, version_code, send_time, ip_address, service_name, lifetime_registration_count, current_registrant_count, creation_time) VALUES(?, ?, ?, ?, ?, ?, ?, ?);");

	ps.setShort(1, this.getComponentCode());
	ps.setShort(2, this.getPacketVersion());
	ps.setTimestamp(3, new Timestamp(this.getTimestamp()));
	ps.setString(4, Util.getAddressAsString(getHostIP()));

        ps.setString(5, this.serviceName);
	ps.setLong(6, this.lifetimeRegistrationCount);
        ps.setLong(7, this.currentRegistrantCount);
	ps.setLong(8, this.resourceCreationTime.getTime());

	return ps;
    }    
} 
