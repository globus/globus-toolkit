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
import org.globus.usage.receiver.handlers.PacketHandler;

public class ReceiverThread extends Thread {
    private static Log log = LogFactory.getLog(ReceiverThread.class);
    protected DatagramSocket socket = null;
    protected int listeningPort;
    private RingBuffer theRing; /*a reference to the one in Receiver*/
    private boolean stillGood = true;
    private int packetsLost;
    private int packetsReceived;

    public ReceiverThread(RingBuffer ringBuffer, Properties props) throws IOException {
        super("ReceiverThread");

        this.listeningPort = Integer.parseInt(props.getProperty("listening-port", "4810"));
        this.theRing = ringBuffer;
        socket = new DatagramSocket(listeningPort);
        log.info("Receiver is listening on port " + listeningPort);
        this.packetsLost = 0;
        this.packetsReceived = 0;
    }

    public void run() {
        byte[] buf;
        DatagramPacket packet;
        CustomByteBuffer storage;

        long period = 1000 * 60 * 5;
        long lastTime = System.currentTimeMillis() + period;

        buf = new byte[UsageMonitorPacket.MAX_PACKET_SIZE];
        /* this is a reusable receiving buffer big enough to hold any
	       packet.  After receiving the packet, put it into a CustomByteBuffer
	       only as large as the packet data itself, so as to avoid writing
	       tons of zero bytes into the database. */
        while(stillGood) {

            packet = new DatagramPacket(buf, buf.length);

            try {
                socket.receive(packet);
                storage = CustomByteBuffer.fitToData(buf, packet.getLength());
                log.debug("Packet received");
                this.packetsReceived++;
                
                /*Put packet into ring buffer:*/
                if (!theRing.insert(storage)) {
                    //failed == ring is full
                    log.error("Ring buffer is FULL.  We are LOSING PACKETS!");
                    this.packetsLost ++;
                }

                if (System.currentTimeMillis() > lastTime) {
                    log.info("Queue size: " + theRing.getNumObjects());
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
    
    public int getPacketsReceived() {
        return this.packetsReceived;
    }
    
    public void resetCounts() {
        this.packetsLost = 0;
        this.packetsReceived = 0;
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
