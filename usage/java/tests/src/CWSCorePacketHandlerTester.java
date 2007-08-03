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

import org.globus.usage.packets.CWSMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.receiver.handlers.CCorePacketHandler;

public class CWSCorePacketHandlerTester extends TestCase {
    static private java.util.Random random = new java.util.Random();
    static private CCorePacketHandler handler = null;
    
    public CWSCorePacketHandlerTester(String name) {
	super(name);
    }

    public void setUp() throws Exception {
        String dburl = System.getProperty("dburl");

        java.util.Properties props = new java.util.Properties();

        handler = new CCorePacketHandler(props);
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

    /** Create a packet, turn it into a buffer, then call the GRAM handler's
      * instantiatePacket method to create a copy of it, then compare the
      * packets.
      */
    public void testInstantiatePacket() {
        CWSMonitorPacket packet;
        File packetFile = new File("packets" + File.separator + "cwscore");
        byte [] data = readPacket(packetFile);
        CustomByteBuffer buf = CustomByteBuffer.wrap(data);

        /* Is this the intended design? */
        packet = (CWSMonitorPacket) handler.instantiatePacket(buf);
        packet.parseByteArray(buf.array());

        Assert.assertEquals("Component codeshould be 4",
                            packet.getComponentCode(), 4);
        Assert.assertEquals(packet.getPacketVersion(), 1);
    }

    public void testGramHandler() {
        CWSMonitorPacket packet;
        File packetFile = new File("packets" + File.separator + "cwscore");
        byte [] data = readPacket(packetFile);
        CustomByteBuffer buf = CustomByteBuffer.wrap(data);

        /* Is this the intended design? */
        packet = (CWSMonitorPacket) handler.instantiatePacket(buf);
        packet.parseByteArray(buf.array());


        handler.handlePacket(packet);
    }
}
