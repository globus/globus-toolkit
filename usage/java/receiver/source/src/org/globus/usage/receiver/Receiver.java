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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
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

public class Receiver {
    private static final String defaultHandlers =
            "org.globus.usage.receiver.handlers.CCorePacketHandler " +
            "org.globus.usage.receiver.handlers.CCorePacketHandlerV2 " +
            "org.globus.usage.receiver.handlers.GRAMPacketHandler " +
            "org.globus.usage.receiver.handlers.GridFTPPacketHandler " +
            "org.globus.usage.receiver.handlers.JavaCorePacketHandler " +
            "org.globus.usage.receiver.handlers.JavaCorePacketHandlerV2 " +
            "org.globus.usage.receiver.handlers.JavaCorePacketHandlerV3 " +
            "org.globus.usage.receiver.handlers.MDSAggregatorPacketHandler " +
            "org.globus.usage.receiver.handlers.RFTPacketHandler " +
            "org.globus.usage.receiver.handlers.RLSPacketHandler " +
            "org.globus.usage.receiver.handlers.OGSADAIPacketHandler " +
            "org.globus.usage.receiver.handlers.DRSPacketHandler " +
            "org.globus.usage.receiver.handlers.MPIGPacketHandler";

    private static Log log = LogFactory.getLog(Receiver.class);
    public static final int DEFAULT_PORT = 4810;
    public static final String DEFAULT_PORT_STRING = "4810";
    private final static String RING_BUFFER_SIZE_STRING = "1024";
    private final static int RING_BUFFER_SIZE = 1024;

    private Date lastResetDate;
    
    RingBuffer theRing; /* receiver thread puts packets in here; handler
                           thread reads them out and pass them through the 
                           handlers.*/
    ReceiverThread theRecvThread;
    HandlerThread theHandleThread;
    
    /*Creates a receiver which will listen on the given port and write
      packets to the given database.*/
    public Receiver(Properties props) 
        throws IOException {

        int ringBufferSize;
        
        try
        {
            ringBufferSize = Integer.parseInt(props.getProperty("ringbuffer-size",
                                              RING_BUFFER_SIZE_STRING));

            if (ringBufferSize <= 0)
            {
                ringBufferSize = RING_BUFFER_SIZE;
            }
        }
        catch(Exception e)
        {
            ringBufferSize = RING_BUFFER_SIZE;
        }

        theRing = new RingBufferFile(ringBufferSize);

        /*Start two threads: a listener thread which listens on the port, and
          a handler thread to take packets out of the ring buffer and
          pass them through all registered handlers...*/

        if (props.getProperty("database-url") != null)
        {
            props.setProperty("database-pool", DatabaseHandlerThread.dbPoolName);
            theHandleThread = new DatabaseHandlerThread(theRing, props);
        }
        else
        {
            theHandleThread = new HandlerThread(theRing, props);
        }
        theHandleThread.start();

        theRecvThread = new ReceiverThread(theRing, props);
        theRecvThread.start();

        lastResetDate = new Date();
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
        int unknownPackets =  this.theHandleThread.getUnknownPackets();
        int packetsReceived = this.theRecvThread.getPacketsReceived();
        int packetsLost = this.theRecvThread.getPacketsLost();
        String newline = System.getProperty("line.separator");

        buf.append(packetsReceived);
        buf.append(" packets received.");
        buf.append(newline);
        
        buf.append(packetsLogged);
        buf.append(" packets successfully logged.");
        buf.append(newline);

        buf.append(unparsablePackets);
        buf.append(" packets received that could not be parsed.");
        buf.append(newline);
        
        buf.append(unknownPackets);
        buf.append(" unrecognized packets.");
        buf.append(newline);
        
        buf.append(packetsLost);
        buf.append(" packets were lost due to buffer overflow.");
        buf.append(newline);

        buf.append("Since ");
        buf.append(this.lastResetDate.toString());
        buf.append(newline);
        buf.append(newline);
        
        buf.append("Breakdown by component:");
        buf.append(newline);

        // Now we have to loop through all registered handlers, combine the
        // strings, append...
        String handlerStatus = theHandleThread.getStatus(doReset);

        buf.append(handlerStatus);
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

    public static void main(String[] args) {
        int port = 0;
        String databaseURL;
        Properties props = new Properties();
        InputStream propsIn;
        String USAGE = "USAGE: globus-usage-receiver [-help] [port]";
        final Receiver receiver;

        // Open properties file (which gets compiled into jar) to read
        // default port and database connection information:

        String file = "/etc/globus_usage_receiver/receiver.properties";
        propsIn = Receiver.class.getResourceAsStream(file);
        if (propsIn == null) {
            System.err.println("Can't open properties file: " + file);
            System.exit(1);
        }

        int controlPort = 4811;

        try {
            props.load(propsIn);
            
            databaseURL = props.getProperty("database-url");

            if (props.getProperty("control-port") != null) {
                controlPort = Integer.parseInt(
                                      props.getProperty("control-port"));
            }

            for (int i = 0; i < args.length; i++) {
                if ((args[i].compareToIgnoreCase("-help") == 0) ||
                    (args[i].compareToIgnoreCase("-h") == 0) ||
                    (args[i].compareToIgnoreCase("--help") == 0)) {
                    System.out.println(USAGE);
                    System.exit(0);
                } else if (i != (args.length - 1)) {
                    System.err.println("Unknown parameter " + args[i]);
                    System.err.println(USAGE);
                    System.exit(1);
                } else {
                    try {
                        port = Integer.parseInt(args[i]);
                        props.setProperty("listening-port", args[i]);

                        if (port < 0 || port > 65536) {
                            System.err.println("Illegal port number " + args[i]);
                            System.exit(1);
                        }
                    } catch (NumberFormatException e) {
                        System.err.println("Unknown parameter " + args[i]);
                        System.err.println(USAGE);
                        System.exit(1);
                    }
                }
            }

            if (port == 0) {
                port = Integer.parseInt(
                        props.getProperty("listening-port", DEFAULT_PORT_STRING));
            }
            
            if (props.getProperty("handlers") == null) {
                log.warn("Using default handler set");
                props.setProperty("handlers", defaultHandlers);
            }

            int ringBufferSize;
            
            try
            {
                ringBufferSize = Integer.parseInt(props.getProperty("ringbuffer-size",
                                                  RING_BUFFER_SIZE_STRING));

                if (ringBufferSize <= 0)
                {
                    ringBufferSize = RING_BUFFER_SIZE;
                }
            }
            catch(Exception e)
            {
                ringBufferSize = RING_BUFFER_SIZE;
            }
            
            
            /* When creating the receiver, pass it the port to listen on,
               the database connection class to use, the url to connect to your
               database, and the database table where default packets will be
               written if no other handler takes them: */
            System.out.println("Starting receiver on port "+port);
            System.out.println("Database address "+databaseURL);
            System.out.println("Ringbuffer size is "+ringBufferSize);
            
            receiver = new Receiver(props);
            
            Thread shutdownThread = (new Thread() {
                public void run() {
                    System.out.println("Shutting down...");
                    receiver.shutDown();
                }
            });
            Runtime.getRuntime().addShutdownHook(shutdownThread);

	    //start the control socket thread:
	    new ControlSocketThread(receiver, controlPort).start();
            System.out.println("Starting control socket at: "  + controlPort);
        }
        catch (IOException e) {
            log.fatal("An IOException occurred when trying to create Receiver:" +e.getMessage());
        }
        catch (Exception e) {
            log.fatal("An exception occurred: " + e.getMessage(), e);
        }

        /*That's all... this thread ends, but the receiver has started listener
          and handler threads which will write incoming packets to the database.*/
    }
}

/*Thread used for interprocess communication, so that the receiver can be
  started/stopped/monitored remotely.  Accepts TCP socket connections on the control port.*/
class ControlSocketThread extends Thread {

    private ServerSocket serverSocket;
    private boolean shutDown;
    private Receiver receiver;

    static Log log = LogFactory.getLog(ControlSocketThread.class);

    public ControlSocketThread (Receiver receiver, int controlPort) 
        throws IOException {
        super("ReceiverControlThread");

	this.receiver = receiver;
	this.shutDown = false;

        this.serverSocket = new ServerSocket(controlPort);
    }

    public void run() {
	/*When we get a connection on the control socket, either respond with
	  the receiver.getStatus(), or shut down the receiver.*/

	PrintWriter out;
	BufferedReader in;
	String inputLine, outputLine;

	while (!shutDown) {
            Socket clientSocket = null;
	    try {
		clientSocket = serverSocket.accept();
		out = new PrintWriter(clientSocket.getOutputStream(), true);
		in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

                inputLine = in.readLine();
                if (inputLine != null) {
                    if (inputLine.equals("check")) {
                        out.println(receiver.getStatus(false));
                    } else if (inputLine.equals("clear")) {
                        out.println(receiver.getStatus(true));
                    } else if (inputLine.equals("stop")) {
                        allShutDown();
                        out.println("OK");
		    } else if (inputLine.equals("flush")) {
			if (receiver.theRing instanceof RingBufferFile) {
			    ((RingBufferFile) receiver.theRing).flush();
			    out.println("Flushed");
			}
			out.println("N/A");
                    } else {
                        out.println("Error: Invalid command");
                    }
                }
		out.close();
	    } catch (IOException e) {
		log.error("Error processing control request", e);
	    } finally {
                if (clientSocket != null) {
                    try {
                        clientSocket.close();
                    } catch (Exception e) {}
                }
            }
	}

	try {
	    serverSocket.close();
	} catch (Exception e) {}
    }

    /*Shuts down both this thread and the receiver.*/
    public void allShutDown() {
	this.shutDown = true;
	receiver.shutDown();
    }
}
