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
import java.lang.reflect.Constructor;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
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

public class PacketClassifier extends DatabaseHandlerThread {
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

    private static Log log = LogFactory.getLog(PacketClassifier.class);
    protected LinkedList handlerList;

    public PacketClassifier(Properties props)
        throws IOException {
        super(null, props);
        theDefaultHandler = null;
        handlerList = new LinkedList();

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
    private void tryHandlers(CustomByteBuffer bufFromRing,
                             short componentCode,
                             short versionCode)
    throws Exception {
        UsageMonitorPacket packet;
        boolean hasBeenHandled;
        PacketHandler handler;
        ListIterator it;

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
            throw new Exception("Unhandled packet " + componentCode + " " + versionCode);
        }
    }


    public static void main(String[] args) {
        String databaseURL;
        Properties props = new Properties();
        InputStream propsIn;
        String USAGE = "USAGE: globus-packet-classifier [-help] ";
        final PacketClassifier pc;

        String file = "/etc/globus_usage_receiver/receiver.properties";
        propsIn = Receiver.class.getResourceAsStream(file);
        if (propsIn == null) {
            System.err.println("Can't open properties file: " + file);
            System.exit(1);
        }

        try {
            props.load(propsIn);
            
            databaseURL = props.getProperty("database-url");

            for (int i = 0; i < args.length; i++) {
                if ((args[i].compareToIgnoreCase("-help") == 0) ||
                    (args[i].compareToIgnoreCase("-h") == 0) ||
                    (args[i].compareToIgnoreCase("--help") == 0)) {
                    System.out.println(USAGE);
                    System.exit(0);
                } else {
                    System.err.println("Unknown parameter " + args[i]);
                    System.err.println(USAGE);
                    System.exit(1);
                }
            }

            if (props.getProperty("handlers") == null) {
                log.warn("Using default handler set");
                props.setProperty("handlers", defaultHandlers);
            }

            
            props.setProperty("database-pool", dbPoolName);

            pc = new PacketClassifier(props);
            
            Connection con = DriverManager.getConnection(
                    dbPoolName);
            Connection removeCon = DriverManager.getConnection(
                    dbPoolName);

            PreparedStatement ps = con.prepareStatement("SELECT id, componentcode, versioncode, contents FROM unknown_packets");
            PreparedStatement rm = removeCon.prepareStatement(
                        "DELETE FROM unknown_packets WHERE id = ?");

            ResultSet rs = ps.executeQuery();

            int okPackets = 0;
            int badPackets = 0;
            while (rs.next()) {
                int id = rs.getInt(1);
                short componentCode  = rs.getShort(2);
                short versionCode = rs.getShort(3);
                byte [] contents = rs.getBytes(4);

                CustomByteBuffer b = CustomByteBuffer.wrap(contents);

                componentCode = b.getShort();
                versionCode = b.getShort();
                b.rewind();

                try {
                    pc.tryHandlers(b, componentCode, versionCode);
                    rm.setInt(1, id);
                    rm.executeUpdate();
                    okPackets++;
                    System.err.print(".");
                } catch (Exception e) {
                    badPackets++;
                    System.err.println(e);
                    System.err.print("-");
                }
            }
            rs.close();

            System.out.println("Successfully processed " + okPackets + " packets");
            System.out.println("Failed to process " + badPackets + " packets");
        }
        catch (IOException e) {
            log.fatal(e);
        }
        catch (Exception e) {
            log.fatal(e);
        }
    }
}
