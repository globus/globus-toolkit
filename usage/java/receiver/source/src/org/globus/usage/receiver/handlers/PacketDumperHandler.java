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

package org.globus.usage.receiver.handlers;

import java.io.File;
import java.io.FileOutputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.usage.receiver.HandlerThread;

public class PacketDumperHandler implements PacketHandler {
    private static Log log = LogFactory.getLog(PacketDumperHandler.class);
    private static int packetCount;

    public PacketDumperHandler(Properties props) {
        packetCount = 0;
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return true;
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        try {
            File f = new File("packet-" + Integer.toString(packetCount++));
            FileOutputStream fo = new FileOutputStream(f);

            byte[] bytes = rawBytes.getRemainingBytes();

            rawBytes.rewind();

            fo.write(bytes);

            fo.close();
        } catch (java.io.IOException ioe) {
            log.error(ioe);
        }

        return new UsageMonitorPacket();
    }
   
    public void resetCounts() {
    }

    public String getDescription() {
        return "";
    }

    public String getStatus() {
        return "";
    }
 
    public void handlePacket(UsageMonitorPacket pack) {
    }

    public void shutDown() {
    }
}
