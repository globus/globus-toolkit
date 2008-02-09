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

import org.globus.usage.packets.CustomByteBuffer;

public class ContainerUsagePacketV3 extends ContainerUsageBasePacket {
    
    public static final short PACKET_VERSION = 3;
    public static final short START_EVENT = 1;
    public static final short STOP_EVENT = 2;
    public static final short UPDATE_EVENT = 3;
    public static final short JVM_INFO_LEN = 64;
    
    protected short versionMajor = -1;
    protected short versionMinor = -1;
    protected short versionMicro = -1;          
    protected int uptime = -1;
    protected int portNumber = -1;
    protected short threadPoolSize = -1;
    protected short threadCount = -1;
    protected short maxThreads = -1;
    protected short threadsHighWaterMark = -1;   
    protected int serviceRequestCount = -1;    
    protected String jvmInfo = null;    
    protected String list = null;
    
    public ContainerUsagePacketV3(short eventType) {
        super(eventType);
        setPacketVersion(PACKET_VERSION);
    }

    public void setVersion(int major, int minor, int micro) {
        this.versionMajor = (short)major;
        this.versionMinor = (short)minor;
        this.versionMicro = (short)micro;
    }
    
    public short getMajorVersion() {
        return this.versionMajor;
    }
   
    public short getMinorVersion() {
        return this.versionMinor;
    }
        
    public short getMicroVersion() {
        return this.versionMicro;
    }   
            
    public void setUptime(int value) {
        this.uptime = value;
    }

    public int getUptime() {
        return this.uptime;
    }
    
    public void setPortNumber(int value) {
        this.portNumber = value;
    }

    public int getPortNumber() {
        return this.portNumber;
    }

    public void setThreadPoolSize(int value) {
        this.threadPoolSize = (short)value;
    }

    public short getThreadPoolSize() {
        return this.threadPoolSize;
    }
    
    public void setCurrentThreadCount(int value) {
        this.threadCount = (short)value;
    }

    public short getCurrentThreadCount() {
        return this.threadCount;
    }
    
    public void setMaxThreadCount(int value) {
        this.maxThreads = (short)value;
    }

    public short getMaxThreadCount() {
        return this.maxThreads;
    }
    
    public void setThreadsHighWaterMark(int value) {
        this.threadsHighWaterMark = (short)value;
    }

    public short getThreadsHighWaterMark() {
        return this.threadsHighWaterMark;
    }
    
    public void setServiceRequestCount(int value) {
        this.serviceRequestCount = value;
    }

    public int getServiceRequestCount() {
        return this.serviceRequestCount;
    }    
        
    public void setServiceList(String list) {
        this.list = list;
    }
    
    public String getServiceList() {
        return this.list;
    }
    
    public void setJvmInfo(String jvmInfo) {
        this.jvmInfo = jvmInfo;
    }
    
    public String getJvmInfo() {
        return this.jvmInfo;
    }

    public void packCustomFields(CustomByteBuffer buf) {
        super.packCustomFields(buf);

        buf.putShort(this.versionMajor);
        buf.putShort(this.versionMinor);
        buf.putShort(this.versionMicro);        
        buf.putInt(this.uptime);
        buf.putInt(this.portNumber);
        buf.putShort(this.threadPoolSize);
        buf.putShort(this.threadCount);
        buf.putShort(this.threadsHighWaterMark);
        buf.putShort(this.maxThreads);        
        buf.putInt(this.serviceRequestCount);        

        if (this.getEventType() == START_EVENT) {
            // write JVM info string
            StringBuffer info = new StringBuffer(this.jvmInfo);
            info.setLength(JVM_INFO_LEN);           
            byte [] jvmData = info.toString().getBytes();
            buf.put(jvmData, 0, info.length());       
        }
        
        // write service list
        byte [] listData = this.list.getBytes();
        buf.putShort((short)listData.length);
        int maxLen = Math.min(listData.length, buf.remaining());
        buf.put(listData, 0, maxLen);
    }
    
    public void unpackCustomFields(CustomByteBuffer buf) {
        super.unpackCustomFields(buf);

        this.versionMajor = buf.getShort();
        this.versionMinor = buf.getShort();
        this.versionMicro = buf.getShort();        
        this.uptime = buf.getInt();        
        this.portNumber = buf.getInt();
        this.threadPoolSize = buf.getShort();
        this.threadCount = buf.getShort();
        this.threadsHighWaterMark = buf.getShort();        
        this.maxThreads = buf.getShort();
        this.serviceRequestCount = buf.getInt();
        
        if (this.getEventType() == START_EVENT) {        
            // read JVM info string
            byte [] jvmData = new byte[JVM_INFO_LEN];
            buf.get(jvmData);
            this.jvmInfo = new String(jvmData);        
        }
        
        // read service list
        short len = buf.getShort();
        int maxLen = Math.min(len, buf.remaining());
        byte [] listData = new byte[maxLen];
        buf.get(listData);
        this.list = new String(listData);
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        buf.append(super.toString());
        buf.append(", Java WS Core version: " + 
                   getMajorVersion() + "." + 
                   getMinorVersion() + "." + 
                   getMicroVersion());
        buf.append(", uptime (seconds): " + 
                   this.getUptime());
        buf.append(", port number: " + 
                   this.getPortNumber());
        buf.append(", initial thread pool size: " + 
                   this.getThreadPoolSize());
        buf.append(", current thread pool size: " + 
                   this.getCurrentThreadCount());
        buf.append(", maximum thread pool size (idle): " + 
                   this.getThreadsHighWaterMark());
        buf.append(", maximum thread pool size (active): " + 
                   this.getMaxThreadCount());        
        buf.append(", requests since last update: " + 
                   this.getServiceRequestCount());  
        String info = this.getJvmInfo();
        if ((info != null) && (info.length() > 0)) {
            buf.append(", JVM information: " + info); 
        }
        String services = this.getServiceList();
        if ((services != null) && (services.length() > 0)) {
            if (this.getEventType() == START_EVENT) {
                buf.append(", services deployed: " + services);            
            } else if (this.getEventType() == STOP_EVENT) {
                buf.append(", services active: " + services);            
            } else if (this.getEventType() == UPDATE_EVENT) {
                buf.append(", services activated: " + services);            
            }
        }
        return buf.toString();
    }

}
