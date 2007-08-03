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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Date;

/*RFT usage monitor packets, in addition to the fields in IPTimeMonitorPacket,
include the following:
    - RFT Factory start time
    - transfer request created timestamp
    - request type (transfer,delete)
    - total number of files transferred
    - total number of bytes transferred
    - total number of RFT resources created
    - fault class name or identifier if Failed
*/
public class RFTUsageMonitorPacket extends IPTimeMonitorPacket {
    static Log log = LogFactory.getLog(RFTUsageMonitorPacket.class);

    private static short COMPONENT_CODE = 5;
    private static short PACKET_VERSION = 1;

    public final static byte TRANSFER = 0;
    public final static byte DELETE = 1;
    private byte requestType; 
    private long numberOfFiles;
    private long numberOfBytes;
    private long numberOfResources;
    private Date resourceCreationTime;
    private Date factoryStartTime;

    public RFTUsageMonitorPacket() {
        setComponentCode(COMPONENT_CODE);
        setPacketVersion(PACKET_VERSION);
    }
    public long getNumberOfFiles() {
        return this.numberOfFiles;
    }
    public void setNumberOfFiles(long numberOfFiles) {
        this.numberOfFiles = numberOfFiles;
    }
    public long getNumberOfBytes() {
        return this.numberOfBytes;
    }
    public void setNumberOfBytes(long numberOfBytes) {
        this.numberOfBytes = numberOfBytes;
    }
    public long getNumberOfResources() {
        return this.numberOfResources;
    }
    public void setNumberOfResources(long numberOfResources) {
        this.numberOfResources = numberOfResources;
    }
    public Date getResourceCreationTime() {
        return this.resourceCreationTime;
    }
    public void setResourceCreationTime(Date resourceCreationTime) {
        this.resourceCreationTime = resourceCreationTime;
    }
    public Date getFactoryStartTime() {
        return this.factoryStartTime;
    }
    public void setFactoryStartTime(Date factoryStartTime) {
        this.factoryStartTime = factoryStartTime;
    }
    public void setRequestType(byte requestType) {
        this.requestType = requestType;
    }
    public boolean isTransfer() {
        return this.requestType == TRANSFER;
    }
    public boolean isDelete() {
        return this.requestType == DELETE;
    }
    public void packCustomFields(CustomByteBuffer buf) {
        super.packCustomFields(buf);
        buf.put(this.requestType);
        buf.putLong(this.numberOfFiles);
        buf.putLong(this.numberOfBytes);
        buf.putLong(this.numberOfResources);
        buf.putLong(this.resourceCreationTime.getTime());
        buf.putLong(this.factoryStartTime.getTime());
    }

    public void unpackCustomFields(CustomByteBuffer buf) {
        super.unpackCustomFields(buf);
        this.requestType = buf.get();
        this.numberOfFiles = buf.getLong();
        this.numberOfBytes = buf.getLong();
        this.numberOfResources = buf.getLong();
        this.resourceCreationTime = new Date(buf.getLong());
        this.factoryStartTime = new Date(buf.getLong());
    }

    public void display() {
        log.info(super.toString());
        log.info("Request Type : " + this.requestType);
        log.info("Number of Files : " + this.numberOfFiles);
        log.info("Number of Bytes : " + this.numberOfBytes);
        log.info("Number of RFT Resources : " + this.numberOfResources);
        log.info("Resource creation Time: " + this.resourceCreationTime);
        log.info("RFT Factory start time : " + this.factoryStartTime);
    }
} 
