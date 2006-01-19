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
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/*
 * To the component code and packet version number fields in the
 * base class, this subclass adds source IP and time-sent fields.
 * It uses a 1-byte flag to indicate whether it holds an IPv4 address
 * (32 bits) or an IPv6 address (128 bits).
 * If you want to include these in your packets, make your packet
 * format a subclass of IPTimeMonitorPacket.
 */
public class IPTimeMonitorPacket extends UsageMonitorPacket {

    private static Log log = 
        LogFactory.getLog(IPTimeMonitorPacket.class.getName());

    private static final byte[] UNKNOWN_SENDER = {0, 0, 0, 0};

    protected long timeSent;
    protected InetAddress senderAddress;

    public void setDateTime(Date d) {
        this.timeSent = d.getTime();
    }
    
    public Date getDateTime() {
        return new Date(this.timeSent);
    }

    public long getTimestamp() {
        return this.timeSent;
    }

    public void setTimestamp(long time) {
        this.timeSent = time;
    }
    
    public void setHostIP(InetAddress addr) {
        this.senderAddress = addr;
    }
    
    public InetAddress getHostIP() {
        return this.senderAddress;
    }

    public void packCustomFields(CustomByteBuffer buf) {
        super.packCustomFields(buf);

        buf.putLong(this.timeSent);
        
        byte[] addressByteArray = (this.senderAddress == null) ? 
            UNKNOWN_SENDER : this.senderAddress.getAddress();
        if (addressByteArray.length == 4) {
            log.debug("This outgoing packet is IPv4.");
            buf.put((byte)4);
        } else if (addressByteArray.length == 16) {
            log.debug("This outgoing packet is IPv6.");
            buf.put((byte)6);
        }
        
        buf.put(addressByteArray);
    }

    public void unpackCustomFields(CustomByteBuffer buf) {

        super.unpackCustomFields(buf);

        this.timeSent = buf.getLong();
        
        byte ipVersion = buf.get();
        byte [] addressByteArray = null;
        if (ipVersion == 4) {
            addressByteArray = new byte[4];
            buf.get(addressByteArray);
        } else if (ipVersion == 6) {
            addressByteArray = new byte[16];
            buf.get(addressByteArray);
        }

        if (addressByteArray == null) {
            log.error("IP version code neither 4 nor 6; can't proceed");
	    this.senderAddress = null;
        } else {
            try {
                this.senderAddress = 
                    InetAddress.getByAddress(addressByteArray);
            } catch (UnknownHostException uhe) {
                log.error("This packet came from a host I can't identify");
            }
        }
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        buf.append(super.toString());
        buf.append(", sent at: " + getDateTime());
        buf.append(", from: " + getHostIP());
        return buf.toString();
    }

}

