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

import junit.framework.TestCase;
import junit.framework.Test;
import junit.framework.Assert;
import junit.framework.TestSuite;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.SocketException;
import java.io.IOException;
import java.util.Properties;

import org.globus.usage.receiver.HandlerThread;
import org.globus.usage.receiver.RingBuffer;
import org.globus.usage.receiver.RingBufferArray;
import org.globus.usage.receiver.handlers.PacketHandler;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;

public class FakeHandler implements PacketHandler {
    short componentCode;
    short packetVersion;
    public static int handled = 0;
    public static int skipped = 0;

    public FakeHandler(Properties props) {
        componentCode = (short) Integer.parseInt(props.getProperty("component-code"));
        packetVersion = (short) Integer.parseInt(props.getProperty("packet-version"));
    }

    /* Indicate willingness to handle the packet */
    public boolean doCodesMatch(short componentCode, short versionCode) {
        if (componentCode == this.componentCode && 
               versionCode == this.packetVersion) {
            return true;
        } else {
            synchronized (FakeHandler.class) {
                skipped++;
                FakeHandler.class.notify();
            }
            return false;
        }
    }

    /* Allocate the appropriate packet type for the handler to consume */
    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new UsageMonitorPacket();
    }

    /* Handle packet */
    public void handlePacket(UsageMonitorPacket pack) {
        synchronized (FakeHandler.class) {
            handled++;
            FakeHandler.class.notify();
        }
    }

    /* Clear count of handled/dropped packets */
    public void resetCounts() {
        synchronized (FakeHandler.class) {
            handled = 0;
            skipped = 0;
            FakeHandler.class.notify();
        }
    }

    /* Get status string related to handler-specific processing */
    public String getStatus() {
        synchronized (FakeHandler.class) {
            return ("Handled: " + handled + "\nSkipped: " + skipped);
        }
    }
}
