package org.globus.usage.packets;

import java.net.Inet6Address;
import java.nio.ReadOnlyBufferException;
import java.sql.Timestamp;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/*RFT GRAM usage monitor packets, in addition to the fields in IPTimeMonitorPacket,
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

    public final static byte TRANSFER = 0;
    public final static byte DELETE = 1;
    private byte requestType; 
    private long numberOfFiles;
    private long numberOfBytes;
    private long numberOfResources;
    private Date resourceCreationTime;
    private Date factoryStartTime;

    public long getNumberOfFiles() {
        return this.numberOfFiles;
    }
    public void setNumberOfFiles() {
        this.numberOfFiles = numberOfFiles;
    }
    public long getNumberOfBytes() {
        return this.numberOfBytes;
    }
    public void setNumberOfBytes() {
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

    public String toSQL() {
        StringBuffer buffer = new StringBuffer("(");
        buffer.append("request_type,number_of_files,");
        buffer.append("number_of_bytes,number_of_resources,");
        buffer.append("creation_time,factory_start_time)");
        buffer.append(" VALUES ('");
        buffer.append(this.requestType).append("','");
        buffer.append(this.numberOfFiles).append("','");
        buffer.append(this.numberOfBytes).append("','");
        buffer.append(this.numberOfResources).append("','");
        buffer.append(this.resourceCreationTime).append("','");
        buffer.append(this.factoryStartTime).append("')");
        // Is everything string ?
        return buffer.toString();
    }
} 
