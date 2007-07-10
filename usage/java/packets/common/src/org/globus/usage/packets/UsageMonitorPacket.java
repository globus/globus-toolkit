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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.globus.net.DatagramSocketFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/*
 * The basic packet format is:
 * 16 bit component code
 * 16 bit packet version code
 * and then a chunk of binary data, up to max 1472 bytes.
 * Interpretation of data depends on the codes in the first 32 bits.
 * Subclass UsageMonitorPacket to define your own format.
 */
public class UsageMonitorPacket {
    
    private static Log log = 
        LogFactory.getLog(UsageMonitorPacket.class.getName());
    
    public static final int DEFAULT_PORT = 4810;
    public static final int MAX_PACKET_SIZE = 1472; //bytes
    
    protected short componentCode;
    protected short packetVersion;
    protected byte[] binaryContents;
    
    public UsageMonitorPacket() {
    }
    
    public void setComponentCode(short c) {
        this.componentCode = c;
    }
    
    public short getComponentCode() {
        return this.componentCode;
    }
    
    public void setPacketVersion(short v) {
        this.packetVersion = v;
    }
    
    public short getPacketVersion() {
        return this.packetVersion;
    }
    
    public byte[] getBinaryContents () {
        return this.binaryContents;
    }

    /*
     * When defining your own packet type, override packCustomFields to
     * write all your custom data into the ByteBuffer; and override
     * unpackCustomFields to read the data back out of the ByteBuffer in
     * the same order.
     */
    public  void packCustomFields(CustomByteBuffer buf) {
    }

    public void unpackCustomFields(CustomByteBuffer buf) {
    }

    /*
     * To get the byte array suitable for stuffing into a packet:
     */
    private byte[] toByteArray() {
        CustomByteBuffer buf = new CustomByteBuffer(MAX_PACKET_SIZE);
        
        buf.putShort(this.componentCode);
        buf.putShort(this.packetVersion);
        
        packCustomFields(buf);
        
        return buf.array();
    }

    public void parseByteArray(byte[] input) {
        CustomByteBuffer buf = CustomByteBuffer.wrap(input);
        
        this.componentCode = buf.getShort();
        this.packetVersion = buf.getShort();
        
        unpackCustomFields(buf);

        this.binaryContents = input; //save this... it'll go into database.
    }
    
    public void sendPacket(DatagramSocket socket, 
                           InetAddress destination, 
                           int destPort) 
        throws IOException {
        byte[] sendBuf = toByteArray();
        DatagramPacket packet = new DatagramPacket(sendBuf, sendBuf.length,
                                                   destination, destPort);
        socket.send(packet);
    }

    /*
     * Destinations and destPorts must contain the same number of elements.
     * It's possible that some of the destinations are valid while others are
     * null because they could not be resolved, so check each one.
     */
    public void sendPacketToMultiple(DatagramSocket socket, 
                                     InetAddress[] destinations,
                                     int[] destPorts) 
        throws IOException {
        if (destinations.length != destPorts.length) {
            throw new IllegalArgumentException("Number of destinations and destination ports do not match");
        }
        
        byte[] sendBuf = toByteArray();
        
        for (int i=0; i<destinations.length; i++) {
            socket.send(new DatagramPacket(sendBuf,
                                           sendBuf.length,
                                           destinations[i],
                                           destPorts[i]));
        }
    }

    /*
     * If you want to send to the same port on each of the multiple
     * hosts (the most likely case):
     */
    public void sendPacketToMultiple(DatagramSocket socket,
                                     InetAddress[] destinations,
                                     int destPort) 
        throws IOException {
        byte[] sendBuf = toByteArray();
        
        for (int i=0; i<destinations.length; i++) {
            socket.send(new DatagramPacket(sendBuf,
                                           sendBuf.length,
                                           destinations[i],
                                           destPort));
        }
    }

    /*
     * The following version of sendPacket doesn't take a socket -- it
     * creates one and destroys it at the end.  This is not very efficient
     * if you're going to be sending a lot of packets, but it may be
     * convenient.
     */
    public void sendPacket(InetAddress destination, 
                           int destPort) 
        throws IOException {
        DatagramSocketFactory factory = DatagramSocketFactory.getDefault();
        DatagramSocket socket = null;
        try {
            socket = factory.createDatagramSocket();
            sendPacket(socket, destination, destPort);
        } finally {
            if (socket != null) {
                socket.close(); 
            }
        }
    }

    public void sendPacketToMultiple(InetAddress[] destinations,
                                     int[] destPorts) 
        throws IOException {
        DatagramSocketFactory factory = DatagramSocketFactory.getDefault();
        DatagramSocket socket = null;
        try {
            socket = factory.createDatagramSocket();
            sendPacketToMultiple(socket, destinations, destPorts);
        } finally {
            if (socket != null) {
                socket.close(); 
            }
        }
    }

    public void sendPacketToMultiple(InetAddress[] destinations,
                                     int destPort) 
        throws IOException {
        DatagramSocketFactory factory = DatagramSocketFactory.getDefault();
        DatagramSocket socket = null;
        try {
            socket = factory.createDatagramSocket();
            sendPacketToMultiple(socket, destinations, destPort);
        } finally {
            if (socket != null) {
                socket.close(); 
            }
        }
    }

    public void sendPacket(List targets) {
        System.out.println("SEND PACKET CALLED");
        Iterator iter = targets.iterator();
        while(iter.hasNext()) {
            String hostport = (String)iter.next();
            hostport = hostport.trim();
            
            int colon = hostport.indexOf(':');
            String host = null;
            int port = -1;
            if (colon == -1) {
                host = hostport;
                port = DEFAULT_PORT;
            } else {
                host = hostport.substring(0, colon);
                port = Integer.parseInt(hostport.substring(colon+1));
            }
            
            try {
                InetAddress addr = InetAddress.getByName(host);
                System.out.println("SENDING PACKET TO " + addr + ":" + port);
                sendPacket(addr, port);
            } catch (Throwable e) {
                log.debug("Failed to send packet", e);
            }
        }
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        buf.append("component code: " + componentCode);
        buf.append(", component packet version: " + packetVersion);
        return buf.toString();
    }
    
}
