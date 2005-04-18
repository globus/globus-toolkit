/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

package org.globus.usage.receiver;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.LinkedList;
import java.util.ListIterator;

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
    private final static int RING_BUFFER_SIZE = 100;

    RingBuffer theRing; /*receiver thread puts packets in here; handler
                          thread reads them out and pass them through the 
                          handlers.*/
    LinkedList handlerList; /*Every handler in this list gets a crack at
                              the incoming packets.*/
    ReceiverThread theRecvThread;
    HandlerThread theHandleThread;


    /*Creates a receiver which will listen on the given port and write
      packets to the given database.*/
    public Receiver(int port, String driverClass, String dburl,
                    String table, int ringBufferSize) throws IOException {

        theRing = new RingBuffer(ringBufferSize);
        handlerList = new LinkedList();

        /*Start two threads: a listener thread which listens on the port, and
          a handler thread to take packets out of the ring buffer and
          pass them through all registered handlers...*/
        theRecvThread = new ReceiverThread(port, theRing);
        theRecvThread.start();
        theHandleThread = new HandlerThread(handlerList, driverClass, 
					    dburl, table, theRing);
        theHandleThread.start();
    }

    /*Constructor with no specified ringBuffer size uses default*/
    public Receiver(int port, String driverClass, String db, String table)
        throws IOException {

        this(port, driverClass, db, table, RING_BUFFER_SIZE);
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

    public String getStatus() {
	/*Return a string with the following metadata:
	  --Number of packets logged/ number dropped since last call
	  --Number of packets in the ring buffer/size of ring buffer
	*/
	StringBuffer buf = new StringBuffer();
	int packetsDropped = theHandleThread.getPacketsDropped();
	int packetsLogged = theHandleThread.getPacketsLogged();

	buf.append(packetsLogged);
	buf.append(" packets logged. ");
	if (packetsDropped > 0) {
	    buf.append(packetsDropped);
	    buf.append(" packets could not be parsed -- see error log. ");
	}
	buf.append(" Ring buffer is at ");
	buf.append(theRing.getNumObjects());
	buf.append(" out of ");
	buf.append(theRing.getCapacity());
	buf.append(".");
	theHandleThread.resetCounts();
	return buf.toString();
    }

    public void shutDown() {
        log.debug("shutting down receiver.");
        theRecvThread.shutDown();
        theHandleThread.shutDown();
    }
}

/*Should this actually be an inner class of Receiver?*/
class ReceiverThread extends Thread {

    private static Log log = LogFactory.getLog(ReceiverThread.class);

    protected DatagramSocket socket = null;
    protected int listeningPort;
    private RingBuffer theRing; /*a reference to the one in Receiver*/
    private boolean stillGood = true;

    public ReceiverThread(int port, RingBuffer ring) throws IOException {
        super("UDPReceiverThread");

        this.listeningPort = port;
        this.theRing = ring;
        socket = new DatagramSocket(listeningPort);
        log.info("Receiver is listening on port " + port);
    }

    public void run() {
        byte[] buf;
        DatagramPacket packet;
        CustomByteBuffer storage;

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
                log.info("Packet received!");
                
                /*Put packet into ring buffer:*/
                if (!theRing.insert(storage)) {
                    //failed == ring is full
                    log.error("Ring buffer is FULL.  We are LOSING PACKETS!");
                   //todo:  throw an exception?
                }

            } catch (IOException e) {
                log.error("When trying to recieve, an exception occurred:"+e.getMessage());
            }
            /*Todo: if the socket is no longer open here, for some reason,
              should we maybe try to open a new socket?*/
        }

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
