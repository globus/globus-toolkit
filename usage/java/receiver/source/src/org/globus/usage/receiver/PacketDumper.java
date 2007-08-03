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

public class PacketDumper {
    private static final String defaultHandlers =
            "org.globus.usage.receiver.handlers.PacketDumperHandler";

    private static Log log = LogFactory.getLog(PacketDumper.class);
    public static final int DEFAULT_PORT = 4810;
    public static final String DEFAULT_PORT_STRING = "4810";
    private final static String RING_BUFFER_SIZE_STRING = "1024";
    private final static int RING_BUFFER_SIZE = 1024;

    public static void main(String[] args) {
        int port = 0;
        String databaseURL;
        Properties props = new Properties();
        InputStream propsIn;
        final Receiver receiver;

        // Open properties file (which gets compiled into jar) to read
        // default port and database connection information:

        int controlPort = 4811;

        try {
            props.setProperty("handlers", defaultHandlers);
            
            if (props.getProperty("control-port") != null) {
                controlPort = Integer.parseInt(
                                      props.getProperty("control-port"));
            }

            if (args.length == 1) {
                /*Get listening port number from command line*/
                port = Integer.parseInt(args[0]);
                props.setProperty("listening-port", args[0]);
            } else {
                /*or else, read port from properties file:*/
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
            System.out.println("Starting PacketDumper on port "+port);
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
