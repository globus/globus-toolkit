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
import java.util.Calendar;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/*
 *Abstract base class for all monitor packets created by C programs
 *(i.e. GridFTP, C WS Core, RLS.)  These all use similar formatting which
 *is quite different from the Java-style packets which are subclasses of
 *IPTimeMonitorPacket.
 */
public class CStylePacket extends UsageMonitorPacket {

    private static Log log = 
        LogFactory.getLog(IPTimeMonitorPacket.class.getName());

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
	/*This doesn't matter, since this class will never be used
	  to send packets.*/
        super.packCustomFields(buf);

        buf.putInt((int)(this.timeSent/1000));
        byte[] addressByteArray = this.senderAddress.getAddress();        
        buf.put(addressByteArray);
    }

    public void unpackCustomFields(CustomByteBuffer buf) {

        super.unpackCustomFields(buf);
	//component and version codes have already been read for us

	byte[] ipBytes = new byte[16];
        buf.getBytes(ipBytes);
	try {
	    this.senderAddress = 
		InetAddress.getByAddress(ipBytes);
	} catch (UnknownHostException uhe) {
	}

	this.timeSent = readCStyleTimestamp(buf).getTime();
    }

    protected PacketFieldParser parseTextSection(CustomByteBuffer buf) {
	String contents = new String(buf.getRemainingBytes());
	PacketFieldParser parser = new PacketFieldParser(contents);
	return parser;
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        buf.append(super.toString());
        buf.append(", sent at: " + getDateTime());
        buf.append(", from: " + getHostIP());
        return buf.toString();
    }

    protected Date readCStyleTimestamp(CustomByteBuffer buf) {
	/*C-style packets use C/Unix-style timestamps:
	  4-byte unsigned number of seconds since midnight, January 1,
	  1970.*/

	Calendar epoch;
	int secondsSinceEpoch;
	epoch = Calendar.getInstance();
        secondsSinceEpoch = buf.getIntBigEndian();
        epoch.set(1970, 0, 0, 0, 0, 0);
        epoch.set(Calendar.MILLISECOND, 0);
        epoch.add(Calendar.SECOND, secondsSinceEpoch);
        if (secondsSinceEpoch < 0 ) {
            epoch.add(Calendar.SECOND, Integer.MAX_VALUE);
        }

	return epoch.getTime();
    }
}
