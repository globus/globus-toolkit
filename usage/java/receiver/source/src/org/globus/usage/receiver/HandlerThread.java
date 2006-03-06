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
//import java.net.DatagramPacket;
//import java.net.DatagramSocket;
import java.util.LinkedList;
import java.util.ListIterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.CustomByteBuffer;
//import org.globus.usage.packets.IPTimeMonitorPacket;
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.usage.receiver.handlers.DefaultPacketHandler;
import org.globus.usage.receiver.handlers.PacketHandler;

import java.sql.DriverManager;
//import java.sql.Connection;
//import java.sql.Statement;
//import java.sql.ResultSet;
//import java.sql.SQLException;

import org.apache.commons.pool.ObjectPool;
import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.commons.dbcp.ConnectionFactory;
import org.apache.commons.dbcp.PoolingDriver;
import org.apache.commons.dbcp.PoolableConnectionFactory;
import org.apache.commons.dbcp.DriverManagerConnectionFactory;


public class HandlerThread extends Thread {

    public static final String dbPoolName = "jdbc:apache:commons:dbcp:usagestats";
    private static Log log = LogFactory.getLog(HandlerThread.class);
    private LinkedList handlerList; /*a reference to the one in Receiver*/
    private RingBuffer theRing; /*a reference to the one in Receiver*/
    private boolean stillGood = true;
    private DefaultPacketHandler theDefaultHandler;

    private int packetsLogged, errorCount;

    public HandlerThread(LinkedList list, String driverClass, String dburl, String table, RingBuffer ring) {
        super("UDPHandlerThread");

	this.packetsLogged = 0;
	this.errorCount = 0;
        this.handlerList = list;
        this.theRing = ring;

	try {
	    Class.forName(driverClass);
	    setUpDatabaseConnectionPool(dburl);
	    theDefaultHandler = new DefaultPacketHandler(dburl, table);
	}
	catch (Exception e) {
	    log.error("Can't start handler thread: "+e.getMessage());
	    stillGood = false;
	}
    }

    private void setUpDatabaseConnectionPool(String dburl) throws Exception {
	/*Set up database connection pool:  all handlers which need a 
	  database connection (which, so far, is all handlers) can take
	  connections from this pool.*/
	GenericObjectPool connectionPool = new GenericObjectPool(null);
	ConnectionFactory connectionFactory = new DriverManagerConnectionFactory(dburl, "allcock", "bigio");
	PoolableConnectionFactory poolableConnectionFactory = new PoolableConnectionFactory(connectionFactory, connectionPool, null, null, false, true);
	PoolingDriver driver = new PoolingDriver();
	driver.registerPool("usagestats", connectionPool);
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

    public void resetCounts() {
	this.packetsLogged = 0;
	this.errorCount = 0;
    }

    /*This thread waits on the RingBuffer; when packets come in, it starts
      reading them out and letting the handlers have them.*/
    public void run() {
        short componentCode, versionCode;
        CustomByteBuffer bufFromRing = null;

        while(stillGood) {
	  try {
	      /*If ring is empty, this call will result in a thread wait
		and will not return until there's something to read.*/
            bufFromRing = theRing.getNext();
	    
            componentCode = bufFromRing.getShort();
            versionCode = bufFromRing.getShort();
            bufFromRing.rewind();
	    tryHandlers(bufFromRing, componentCode, versionCode);
	    
	    packetsLogged ++;
	  } catch (Exception e) {
	    //this thread has to be able to catch any exception and keep going...
	    //otherwise a bad packet could shut down the thread!
	    log.error(e.getMessage());
	    if (bufFromRing != null) {
	  	log.error(new String(bufFromRing.array()));
	    }
	    errorCount ++;
	    /*TODO: if this is an I/O exception, i.e. can't talk to database,
	      maybe restart the connection right here.*/
  	  }
	}
    }

    private void debugRawPacketContents(CustomByteBuffer buf) {
	short cc, vc;
	long ts;
	short ipv;

	log.info("HandlerThread got a usagepacket.");	
	cc = buf.getShort();
	vc = buf.getShort();
	log.info("component code = "+cc+", packet version = "+vc);
	ts = buf.getLong();
	log.info("Time sent = "+ts);
	ipv = buf.getShort();
	log.info("IP Version is "+ipv);
	buf.rewind();
    }

    /*Use component code and version code in packet to decide
      which handler to use:*/
    private void tryHandlers(CustomByteBuffer bufFromRing, short componentCode,
                             short versionCode) {
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
            if (!hasBeenHandled) {
                packet = theDefaultHandler.instantiatePacket(bufFromRing);
                packet.parseByteArray(bufFromRing.array());
                theDefaultHandler.handlePacket(packet);
            }
        }
        /*If multiple handlers return true for doCodesMatch, each
          handler will be triggered, each with its own separate copy of
          the packet.  theDefaultHandler will be called only if no other
          handlers trigger.*/        
    }


    public void shutDown() {
        stillGood = false; //lets the loop in run() finish

	try {
	    PoolingDriver driver = (PoolingDriver)DriverManager.getDriver("jdbc:apache:commons:dbcp:");
	    driver.closePool("usagestats");
	}
	catch(Exception e) {
	    log.warn(e.getMessage());
	}
    }
}
