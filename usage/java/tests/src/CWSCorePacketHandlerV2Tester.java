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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.globus.usage.packets.CWSMonitorPacketV2;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.receiver.handlers.CCorePacketHandlerV2;

public class CWSCorePacketHandlerV2Tester extends TestCase {
    static private java.util.Random random = new java.util.Random();
    static private CCorePacketHandlerV2 handler = null;
    
    public CWSCorePacketHandlerV2Tester(String name) {
	super(name);
    }

    public void setUp() throws Exception {
        String dburl = System.getProperty("dburl");

        java.util.Properties props = new java.util.Properties();

        handler = new CCorePacketHandlerV2(props);
    }

    protected byte[] readPacket(File f) {
        byte [] data = null;
        FileInputStream s = null;

        try {
            s = new FileInputStream(f);
            data = new byte[(int) f.length()];

            s.read(data);
        } catch (IOException ioe) {
            Assert.assertEquals(ioe, null);
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (IOException ioe) {
                    Assert.assertEquals(ioe, null);
                }
            }
        }
        return data;
    }

    public void testInstantiateStartPacket() {
        CWSMonitorPacketV2 packet;
        File packetFile = new File("packets" + File.separator + "cwscore2.start");
        byte [] data = readPacket(packetFile);
        CustomByteBuffer buf = CustomByteBuffer.wrap(data);

        /* Is this the intended design? */
        packet = (CWSMonitorPacketV2) handler.instantiatePacket(buf);
        packet.parseByteArray(buf.array());

        Assert.assertEquals("Component codeshould be 4",
                            packet.getComponentCode(), 4);
        Assert.assertEquals(packet.getPacketVersion(), 2);
        Assert.assertEquals(packet.getServices(), "NotificationConsumerService,SubscriptionManagerService");
    }

    public void testInstantiateStopPacket() {
        CWSMonitorPacketV2 packet;
        File packetFile = new File("packets" + File.separator + "cwscore2.stop");
        byte [] data = readPacket(packetFile);
        CustomByteBuffer buf = CustomByteBuffer.wrap(data);

        /* Is this the intended design? */
        packet = (CWSMonitorPacketV2) handler.instantiatePacket(buf);
        packet.parseByteArray(buf.array());

        Assert.assertEquals("Component codeshould be 4",
                            packet.getComponentCode(), 4);
        Assert.assertEquals(packet.getPacketVersion(), 2);
    }

    public void testGramHandler() {
        CWSMonitorPacketV2 packet;
        File packetFile = new File("packets" + File.separator + "cwscore2.start");
        byte [] data = readPacket(packetFile);
        CustomByteBuffer buf = CustomByteBuffer.wrap(data);

        /* Is this the intended design? */
        packet = (CWSMonitorPacketV2) handler.instantiatePacket(buf);
        packet.parseByteArray(buf.array());

        handler.handlePacket(packet);
    }
}
