/*
 * This file or a portion of this file is licensed under the terms of the
 * Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without modifications,
 * you must include this notice in the file.
 */
package org.globus.usage.packets;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

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
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
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
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
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
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            sendPacketToMultiple(socket, destinations, destPort);
        } finally {
            if (socket != null) {
                socket.close(); 
            }
        }
    }

    public void sendPacket(List targets) {
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
                sendPacket(addr, port);
            } catch (IOException e) {
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
