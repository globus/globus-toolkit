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
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Properties;
import java.lang.reflect.Constructor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.usage.receiver.handlers.DefaultPacketHandler;
import org.globus.usage.receiver.handlers.PacketHandler;

import java.sql.DriverManager;

import org.apache.commons.pool.ObjectPool;
import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.commons.dbcp.ConnectionFactory;
import org.apache.commons.dbcp.PoolingDriver;
import org.apache.commons.dbcp.PoolableConnectionFactory;
import org.apache.commons.dbcp.DriverManagerConnectionFactory;


public class HandlerThread extends Thread {
    private static Log log = LogFactory.getLog(HandlerThread.class);
    private LinkedList handlerList; /*a reference to the one in Receiver*/
    private RingBuffer theRing; /*a reference to the one in Receiver*/
    protected boolean stillGood = true;
    protected PacketHandler theDefaultHandler;

    private int packetsLogged;
    private int errorCount;
    private int unknownPackets;

    public HandlerThread(RingBuffer ring, Properties props) {
        super("HandlerThread");

        handlerList = new LinkedList();
        this.theRing = ring;
        this.theDefaultHandler = null;

        String handlerProp = props.getProperty("handlers");

        if (handlerProp == null)
        {
            throw new RuntimeException("handler set not configured");
        }

        String [] handlers = handlerProp.split("\\s");

        Class parameterTypes[] = { java.util.Properties.class };
        Object parameters[] = { props };

        for (int i = 0; i < handlers.length; i++) {
            try {
                Class handlerClass = Class.forName(handlers[i]);
                Constructor constructor = handlerClass.getConstructor(parameterTypes);
                PacketHandler p = (PacketHandler) constructor.newInstance(parameters);

                handlerList.add(p);
            } catch (Exception e) {
                log.error("Error loading handler class for " + handlers[i], e);
            }
        }
    }


    /*The handler thread maintains counts of the number of packets 
      successfully written to database and the number that could not
      be parsed:*/
    public int getPacketsLogged() {
	return this.packetsLogged;
    }
    
    public int getUnparseablePackets() {
	return this.errorCount;
    }

    public int getUnknownPackets() {
        return this.unknownPackets;
    }
    
    public void resetCounts() {
	this.packetsLogged = 0;
	this.errorCount = 0;
        this.unknownPackets = 0;

        ListIterator it = handlerList.listIterator();
        while (it.hasNext()) {
            PacketHandler oneHandler = (PacketHandler)it.next();

            oneHandler.resetCounts();
        }
    }

    /*This thread waits on the RingBuffer; when packets come in, it starts
      reading them out and letting the handlers have them.*/
    public void run() {
        short componentCode, versionCode;
        CustomByteBuffer bufFromRing = null;

        while (stillGood) {
            try {
                /*If ring is empty, this call will result in a thread wait
                  and will not return until there's something to read.*/
                bufFromRing = theRing.getNext();
                if (bufFromRing == null) {
                    break;
                }
                componentCode = bufFromRing.getShort();
                versionCode = bufFromRing.getShort();
                bufFromRing.rewind();

                tryHandlers(bufFromRing, componentCode, versionCode);
	    
                this.packetsLogged ++;
            } catch (Exception e) {
                this.errorCount ++;

                //this thread has to be able to catch any exception and keep
                //going... otherwise a bad packet could shut down the thread!
                log.error("Error during handler processing", e);
                if (bufFromRing != null) {
                    log.error(new String(bufFromRing.array()));
                }
                /*TODO: if this is an I/O exception, 
                  i.e. can't talk to database,
                  maybe restart the connection right here.*/
            }
	}
    }

    /*Use component code and version code in packet to decide
      which handler to use:*/
    private void tryHandlers(CustomByteBuffer bufFromRing,
                             short componentCode,
                             short versionCode)
    throws Exception {
        UsageMonitorPacket packet;
        boolean hasBeenHandled;
        PacketHandler handler;
        ListIterator it;
        
        /*This next bit is synchronized to make sure a handler can't
              be registered while we're walking the list...*/
        synchronized(handlerList) {
            hasBeenHandled = false;                
            for (it = handlerList.listIterator(); it.hasNext(); ) {
                handler = (PacketHandler)it.next();
                if (handler.doCodesMatch(componentCode, versionCode)) {
                    packet = handler.instantiatePacket(bufFromRing);
                    packet.parseByteArray(bufFromRing.array());
                    handler.handlePacket(packet);
                    bufFromRing.rewind();
                    hasBeenHandled = true;
                }
            }
            if ((!hasBeenHandled) && theDefaultHandler != null) {
                packet = theDefaultHandler.instantiatePacket(bufFromRing);
                packet.parseByteArray(bufFromRing.array());
                theDefaultHandler.handlePacket(packet);
                this.unknownPackets++;

                if (log.isDebugEnabled()) {
                    log.debug("Unknown packet: " +
                       DefaultPacketHandler.getPacketContentsBinary(packet));
                }
            } else if (!hasBeenHandled) {
                throw new Exception("Unhandled packet");
            }
        }
        /*If multiple handlers return true for doCodesMatch, each
          handler will be triggered, each with its own separate copy of
          the packet.  theDefaultHandler will be called only if no other
          handlers trigger.*/        
    }

    public void shutDown() {
        stillGood = false; //lets the loop in run() finish
    }

    String getStatus(boolean doReset) {
        StringBuffer buf = new StringBuffer();
        String newline = System.getProperty("line.separator");

        ListIterator it = handlerList.listIterator();
        while (it.hasNext()) {
            PacketHandler oneHandler = (PacketHandler)it.next();
            buf.append(oneHandler.getStatus());
            buf.append(newline);
            if (doReset) {
                oneHandler.resetCounts();
            }
        }
        return buf.toString();
    }
}
