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

import org.globus.usage.packets.IPTimeMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class ContainerUsageBasePacket extends IPTimeMonitorPacket {

    private static Log logger =
        LogFactory.getLog(ContainerUsageBasePacket.class.getName());

    public static final short UNKNOWN = 0;

    public static final short STANDALONE_CONTAINER = 1;
    public static final short SERVLET_CONTAINER = 2;

    public static final short COMPONENT_CODE = 3;
    public static final short PACKET_VERSION = 1;

    private int containerID;
    private short containerType;
    private short eventType;

    public ContainerUsageBasePacket() {
    }

    public ContainerUsageBasePacket(short eventType) {
        setTimestamp(System.currentTimeMillis());
        setComponentCode(COMPONENT_CODE);
        setPacketVersion(PACKET_VERSION);
        setEventType(eventType);
    }

    public void setContainerID(int id) {
        this.containerID = id;
    }

    public int getContainerID() {
        return this.containerID;
    }

    public void setContainerType(short type) {
        this.containerType = type;
    }

    public short getContainerType() {
        return this.containerType;
    }

    protected void setEventType(short type) {
        this.eventType = type;
    }

    public short getEventType() {
        return this.eventType;
    }

    public void packCustomFields(CustomByteBuffer buf) {
        super.packCustomFields(buf);

        buf.putInt(this.containerID);
        buf.putShort(this.containerType);
        buf.putShort(this.eventType);
    }
    
    public void unpackCustomFields(CustomByteBuffer buf) {
        super.unpackCustomFields(buf);

        setContainerID(buf.getInt());
        setContainerType(buf.getShort());
        setEventType(buf.getShort());
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        buf.append(super.toString());
        buf.append(", container id: " + getContainerID());
        buf.append(", container type: " + getContainerType());
        buf.append(", event type: " + getEventType());
        return buf.toString();
    }
}
