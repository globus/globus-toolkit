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

package org.globus.usage.receiver;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Date;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.IPTimeMonitorPacket;
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.usage.receiver.handlers.DefaultPacketHandler;
import org.globus.usage.receiver.handlers.PacketHandler;

public class Receiver {
    private static Log log = LogFactory.getLog(Receiver.class);
    public static final int DEFAULT_PORT = 4810;
    private final static int RING_BUFFER_SIZE = 1024;

    private Date lastResetDate;
    
    RingBuffer theRing; /*receiver thread puts packets in here; handler
                          thread reads them out and pass them through the 
                          handlers.*/
    LinkedList handlerList; /*Every handler in this list gets a crack at
                              the incoming packets.*/
    ReceiverThread theRecvThread;
    HandlerThread theHandleThread;
    

    /*Creates a receiver which will listen on the given port and write
      packets to the given database.*/
    public Receiver(int port, 
                    int ringBufferSize,
                    Properties props) 
        throws IOException {

        theRing = new RingBufferArray(ringBufferSize);
        handlerList = new LinkedList();

        /*Start two threads: a listener thread which listens on the port, and
          a handler thread to take packets out of the ring buffer and
          pass them through all registered handlers...*/
        theRecvThread = new ReceiverThread(port, theRing);
        theRecvThread.start();
        theHandleThread = new HandlerThread(handlerList, theRing, props);
        theHandleThread.start();
	lastResetDate = new Date();
    }

    /*Constructor with no specified ringBuffer size uses default*/
    public Receiver(int port, Properties props) 
        throws IOException {
        this(port, RING_BUFFER_SIZE, props);
    }


    public void registerHandler(PacketHandler myHandler) {

        /*once the handler is registered, it will be called every time a
          packet comes in bearing a matching component code and packet version
          code.  If multiple handlers are installed that handle the same code,
          ALL will be triggered!  Starting with the most recently registered.
        */

        synchronized (handlerList) {
            handlerList.addFirst(myHandler);
        }
        
    }

    /*I don't recommend using this method, which blocks until a packet
      comes in, then returns the packet.  I wrote it just to test the
      receiver*/
    public UsageMonitorPacket blockingGetPacket() {
        CustomByteBuffer bufFromRing;
        UsageMonitorPacket packet;
        short code;

        bufFromRing = theRing.getNext();
        code = bufFromRing.getShort();
        switch (code) {
            case 0:
                packet = new org.globus.usage.packets.GFTPMonitorPacket();
                break;
            case 69:
                packet = new IPTimeMonitorPacket();
                break;
            default:
                packet = new UsageMonitorPacket();
        }

        bufFromRing.rewind();
        packet.parseByteArray(bufFromRing.array());

        return packet;
    }

    public String getStatus(boolean doReset) {
	/*Return a string with the following metadata:
	  --Number of packets logged, total and in each protocol, since last
	    call.
	  --Number of packets unparseable
	  --Number of packets dropped from ring buffer
	  --Date/time from which these numbers were counted.
	*/
	StringBuffer buf = new StringBuffer();
	int unparsablePackets = this.theHandleThread.getUnparseablePackets();
	int packetsLogged = this.theHandleThread.getPacketsLogged();
	int packetsLost = this.theRecvThread.getPacketsLost();
	String newline = System.getProperty("line.separator");

	buf.append(packetsLogged);
	buf.append(" packets received and successfully logged;");
	buf.append(newline);
	buf.append(unparsablePackets);
	buf.append(" packets received that could not be parsed as any known component;");
	buf.append(newline);
	buf.append("And ");
	buf.append(packetsLost);
	buf.append(" packets were lost due to ring buffer overflow,");
	buf.append(newline);
	buf.append(" since ");
	buf.append(this.lastResetDate.toString());
	buf.append(newline);
	buf.append("Breakdown by component:");
	buf.append(newline);

	//Now we have to loop through all registered handlers, combine the strings, append...
	ListIterator it = handlerList.listIterator();
	while (it.hasNext()) {
	    PacketHandler oneHandler = (PacketHandler)it.next();
	    buf.append(oneHandler.getStatus());
	    buf.append(newline);
	    if (doReset) {
		oneHandler.resetCounts();
	    }
	}

	if (doReset) {
	    theRecvThread.resetCounts();
	    theHandleThread.resetCounts();
	    lastResetDate = new Date();
	}

	return buf.toString();
    }

    public void shutDown() {
        log.debug("shutting down receiver.");
        theRecvThread.shutDown();
        try {
            theHandleThread.join();
        } catch (InterruptedException e) {
            // ignore it
        }
    }
}

/*Should this actually be an inner class of Receiver?*/
class ReceiverThread extends Thread {

    private static Log log = LogFactory.getLog(ReceiverThread.class);

    protected DatagramSocket socket = null;
    protected int listeningPort;
    private RingBuffer theRing; /*a reference to the one in Receiver*/
    private boolean stillGood = true;
    private int packetsLost;

    public ReceiverThread(int port, RingBuffer ring) throws IOException {
        super("UDPReceiverThread");

        this.listeningPort = port;
        this.theRing = ring;
        socket = new DatagramSocket(listeningPort);
        log.info("Receiver is listening on port " + port);
	this.packetsLost = 0;
    }

    public void run() {
        byte[] buf;
        DatagramPacket packet;
        CustomByteBuffer storage;

        long period = 1000 * 60 * 5;
        long lastTime = System.currentTimeMillis() + period;

	buf = new byte[UsageMonitorPacket.MAX_PACKET_SIZE];
	/*this is a reusable receiving buffer big enough to hold any
	  packet.  After receiving the packet, put it into a CustomByteBuffer
	  only as large as the packet data itself, so as to avoid writing
	  tons of zero bytes into the database.*/
        while(stillGood) {

            packet = new DatagramPacket(buf, buf.length);

            try {
                socket.receive(packet);

                storage = CustomByteBuffer.fitToData(buf, packet.getLength());
                log.info("Packet received");
                
                /*Put packet into ring buffer:*/
                if (!theRing.insert(storage)) {
                    //failed == ring is full
                    log.error("Ring buffer is FULL.  We are LOSING PACKETS!");
		    this.packetsLost ++;
                }

                if (System.currentTimeMillis() > lastTime) {
                    log.error("Queue size: " + theRing.getNumObjects());
                    lastTime = System.currentTimeMillis() + period;
                }

            } catch (IOException e) {
                if (stillGood) {
                    log.error("Error during receive", e);
                }
            }
            /*Todo: if the socket is no longer open here, for some reason,
              should we maybe try to open a new socket?*/
        }

        theRing.close();
    }

    public int getPacketsLost() {
	return this.packetsLost;
    }
    
    public void resetCounts() {
	this.packetsLost = 0;
    }

    public int getRingFullness() {
	return theRing.getNumObjects();
    }

    public void shutDown() {
        stillGood = false; //lets the loop in run() finish.
	try {
	    socket.close();
	} catch (Exception e) {}
    }
}
