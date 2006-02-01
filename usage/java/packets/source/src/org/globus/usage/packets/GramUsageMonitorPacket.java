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

/*This class should only be used to parse incoming packets for
   database storage.  To create outgoing packets, use
   org.globus.exec.service.usage.GramUsageMonitorPacket.*/

package org.globus.usage.packets;

import java.net.Inet6Address;
import java.nio.ReadOnlyBufferException;
import java.sql.Timestamp;
import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

//import org.globus.exec.generated.JobTypeEnumeration;

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.IPTimeMonitorPacket;

/*GRAM usage monitor packets, in addition to the fields in IPTimeMonitorPacket,
include the following:
    - job created timestamp
    - scheduler type (Fork, PBS, LSF, Condor, SGE, etc...)
    - jobCredentialEndpoint present flag (i.e. do they use server-side user
     proxies)
    - fileStageIn present flag
    - fileStageOut present flag
    - fileCleanUp present flag
    - CleanUpHold flag
    - job type (Single, Multiple, MPI, Condor)
    - gt2 error code if present and Failed
    - fault class name or identifier if Failed
*/
public class GramUsageMonitorPacket
    extends                                 IPTimeMonitorPacket
{
    static Log logger = LogFactory.getLog(GramUsageMonitorPacket.class);

    private static short COMPONENT_CODE = 1;
    private static short PACKET_VERSION = 1;

    private static byte FALSE   = 0;
    private static byte TRUE    = 1;

    //job created timestamp
    private Date creationTime;

    //scheduler type
    private final static int MAX_SCHEDULER_TYPE_SIZE = 20;
    private String localResourceManager;

    //jobCredentialEndpoint present flag
    private boolean jobCredentialEndpointUsed;

    //fileStageIn present flag
    private boolean fileStageInUsed;

    //fileStageOut present flag
    private boolean fileStageOutUsed;

    //fileCleanUp present flag
    private boolean fileCleanUpUsed;

    //CleanUpHold flag
    private boolean cleanUpHoldUsed;

    //job type
    private static final byte JOB_TYPE_UNKNOWN   = 0;
    private static final byte JOB_TYPE_SINGLE    = 1;
    private static final byte JOB_TYPE_MULTIPLE  = 2;
    private static final byte JOB_TYPE_MPI       = 3;
    private static final byte JOB_TYPE_CONDOR    = 4;
    private byte jobType;

    //gt2 error
    private int gt2ErrorCode;

    //fault class name
    private static final byte FAULT_CLASS_UNKNOWN                   = 0;
    private static final byte FAULT_CLASS_CREDENTIAL_SERIALIZATION  = 1;
    private static final byte FAULT_CLASS_EXECUTION_FAILED          = 2;
    private static final byte FAULT_CLASS_FAULT                     = 3;
    private static final byte FAULT_CLASS_FILE_PERMISSIONS          = 4;
    private static final byte FAULT_CLASS_INSUFFICIENT_CREDENTIALS  = 5;
    private static final byte FAULT_CLASS_INTERNAL                  = 6;
    private static final byte FAULT_CLASS_INVALID_CREDENTIALS       = 7;
    private static final byte FAULT_CLASS_INVALID_PATH              = 8;
    private static final byte FAULT_CLASS_SERVICE_LEVEL_AGREEMENT   = 9;
    private static final byte FAULT_CLASS_STAGING                   = 10;
    private static final byte FAULT_CLASS_UNSUPPORTED_FEATURE       = 11;
    private byte faultClass;

    public GramUsageMonitorPacket()
    {
        setComponentCode(COMPONENT_CODE);
        setPacketVersion(PACKET_VERSION);
    }

    public void setCreationTime(Date creationTime)
    {
        this.creationTime = creationTime;
    }

    public Date getCreationTime() {
        return this.creationTime;
    }

    public void setLocalResourceManager(String localResourceManager)
    {
        this.localResourceManager = localResourceManager;
    }

    public String getLocalResourceManager() {
        return this.localResourceManager;
    }

    public void setJobCredentialEndpointUsed(boolean jobCredentialEndpointUsed)
    {
        this.jobCredentialEndpointUsed = jobCredentialEndpointUsed;
    }

    public boolean getJobCredentialEndpointUsed() {
        return this.jobCredentialEndpointUsed;
    }

    public void setFileStageInUsed(boolean FileStageInUsed)
    {
        this.fileStageInUsed = FileStageInUsed;
    }

    public boolean isFileStageInUsed() {
        return this.fileStageInUsed;
    }

    public void setFileStageOutUsed(boolean FileStageOutUsed)
    {
        this.fileStageOutUsed = FileStageOutUsed;
    }

    public boolean isFileStageOutUsed() {
        return this.fileStageOutUsed;
    }

    public void setFileCleanUpUsed(boolean FileCleanUpUsed)
    {
        this.fileCleanUpUsed = FileCleanUpUsed;
    }

    public boolean isFileCleanUpUsed() {
        return this.fileCleanUpUsed;
    }

    public void setCleanUpHoldUsed(boolean CleanUpHoldUsed)
    {
        this.cleanUpHoldUsed = CleanUpHoldUsed;
    }

    public boolean isCleanUpHoldUsed() {
        return this.cleanUpHoldUsed;
    }

    public void setJobType(byte jobType)
    {
        this.jobType = jobType;
    }

    public byte getJobType() {
        return this.jobType;
    }

    public void setGt2ErrorCode(int gt2ErrorCode)
    {
        this.gt2ErrorCode = gt2ErrorCode;
    }

    public int getGt2ErrorCode() {
        return this.gt2ErrorCode;
    }

    public void setFaultClass(byte faultClass)
    {
        this.faultClass = faultClass;
    }

    public byte getFaultClass() {
        return this.faultClass;
    }

    private short getIPVersion()
    {
        if (this.senderAddress instanceof Inet6Address)
            return 6;
        else
            return 4;
    }

    //TODO update everything bellow

    public void packCustomFields(CustomByteBuffer buf)
    {
        super.packCustomFields(buf);

        //creationTime
        buf.putLong(creationTime.getTime());

        //localResourceManager
        int localResourceManagerActualLength = localResourceManager.length();
        String localResourceManagerFixedLength = null;
        if (localResourceManagerActualLength > MAX_SCHEDULER_TYPE_SIZE)
        {
            //truncate localResourceManager string
            localResourceManagerFixedLength
                = localResourceManager.substring(0, MAX_SCHEDULER_TYPE_SIZE);
        }
        else if (localResourceManagerActualLength < MAX_SCHEDULER_TYPE_SIZE)
        {
            //pad localResourceManager string
            localResourceManagerFixedLength
                = localResourceManager
                + new char[MAX_SCHEDULER_TYPE_SIZE - localResourceManagerActualLength];
        }
        else
        {
            //do nothing to localResourceManager string
            localResourceManagerFixedLength = localResourceManager;
        }
        byte[] localResourceManagerFixedBytes = localResourceManagerFixedLength.getBytes();
        buf.put(localResourceManagerFixedBytes);

        //jobCredentialEndpointUsed
        buf.put(this.jobCredentialEndpointUsed?TRUE:FALSE);

        //FileStageInUsed
        buf.put(this.fileStageInUsed?TRUE:FALSE);

        //FileStageOutUsed
        buf.put(this.fileStageOutUsed?TRUE:FALSE);

        //FileCleanUpUsed
        buf.put(this.fileCleanUpUsed?TRUE:FALSE);

        //CleanUpHoldUsed
        buf.put(this.cleanUpHoldUsed?TRUE:FALSE);

        //jobType
        buf.put(this.jobType);

        //gt2ErrorCode
        buf.putInt(this.gt2ErrorCode);

        //faultClass
        buf.put(this.faultClass);
    }
   
    public void unpackCustomFields(CustomByteBuffer buf)
    {
        super.unpackCustomFields(buf);
        //creationTime
        this.creationTime = new Date(buf.getLong());

        //localResourceManager


        /*localResourceManager PROBLEM: How do we know how many bytes
	to read for the localResourceManager?  The binary data after
	the end of this text could look like more letters.  Solution:
	the next byte after the end of the localResourceManager is for
	the boolean jobCredential, so it must be either 0 or 1, which will
	not appear in the string!*/

	this.localResourceManager = buf.getUntilZeroOrOne(MAX_SCHEDULER_TYPE_SIZE);

        //jobCredentialEndpointUsed
        this.jobCredentialEndpointUsed = (buf.get()==1?true:false);

        //FileStageInUsed
        this.fileStageInUsed = (buf.get()==1?true:false);

        //FileStageOutUsed
        this.fileStageOutUsed = (buf.get()==1?true:false);

        //FileCleanUpUsed
        this.fileCleanUpUsed = (buf.get()==1?true:false);

        //CleanUpHoldUsed
        this.cleanUpHoldUsed = (buf.get()==1?true:false);

        //jobType
        this.jobType = buf.get();

        //gt2ErrorCode
        this.gt2ErrorCode = buf.getInt();

        //faultClass
        this.faultClass = buf.get();
    }

    public void display()
    {
        logger.info(super.toString());

        logger.info("creationTime = "+this.creationTime);
        logger.info("localResourceManager = "+this.localResourceManager);
        logger.info("jobCredentialEndpointUsed = "
                    +this.jobCredentialEndpointUsed);
        logger.info("FileStageInUsed = "+fileStageInUsed);
        logger.info("FileStageOutUsed = "+fileStageOutUsed);
        logger.info("FileCleanUpUsed = "+fileCleanUpUsed);
        logger.info("CleanUpHoldUsed = "+cleanUpHoldUsed);
        logger.info("jobType = "+jobType);
        logger.info("gt2ErrorCode = "+gt2ErrorCode);
        logger.info("faultClass = "+faultClass);
    }


    public PreparedStatement toSQL(Connection con, String tablename) throws SQLException {
	PreparedStatement ps;
	ps = con.prepareStatement("INSERT INTO "+tablename+" (component_code, version_code, send_time, ip_address, creation_time, scheduler_type, job_credential_endpoint_used, file_stage_in_used, file_stage_out_used, file_clean_up_used, clean_up_hold_used, job_type, gt2_error_code, fault_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
	
	ps.setShort(1, this.getComponentCode());
	ps.setShort(2, this.getPacketVersion());
	ps.setTimestamp(3, new Timestamp(this.getTimestamp()));

	if (this.getHostIP() == null) {
	    ps.setString(4, "unknown");
	}
	else {
	    ps.setString(4, this.getHostIP().toString());
	}

	ps.setTimestamp(5, new Timestamp(this.creationTime.getTime()));
	ps.setString(6, this.localResourceManager);
	ps.setBoolean(7, this.jobCredentialEndpointUsed);
	ps.setBoolean(8, this.fileStageInUsed);
	ps.setBoolean(9, this.fileStageOutUsed);
	ps.setBoolean(10, this.fileCleanUpUsed);
	ps.setBoolean(11, this.cleanUpHoldUsed);
	ps.setByte(12, this.jobType);
	ps.setInt(13, this.gt2ErrorCode);
	ps.setByte(14, this.faultClass);

	return ps;
    }
}

