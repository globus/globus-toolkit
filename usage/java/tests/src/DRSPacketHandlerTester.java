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

import java.lang.reflect.Method;

import org.globus.usage.packets.DRSUsageMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.receiver.handlers.DRSPacketHandler;

public class DRSPacketHandlerTester extends TestCase {
    static private java.util.Random random = new java.util.Random();
    static private DRSPacketHandler handler = null;
    
    public DRSPacketHandlerTester(String name) {
	super(name);
    }

    public void setUp() throws Exception {
        String dburl = System.getProperty("dburl");

        java.util.Properties props = new java.util.Properties();

        handler = new DRSPacketHandler(props);
    }

    private DRSUsageMonitorPacket createPacket()
            throws java.net.UnknownHostException
    {
        DRSUsageMonitorPacket drsPack = new DRSUsageMonitorPacket();
        java.util.Date now = new java.util.Date();

        try
        {
            drsPack.setHostIP(java.net.InetAddress.getLocalHost());
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return null;
        }
        drsPack.setNumberOfFiles(1);
        drsPack.setNumberOfResources(3);

        return drsPack;
    }

    /** Create a packet, turn it into a buffer, then call the DRS handler's
      * instantiatePacket method to create a copy of it, then compare the
      * packets.
      */
    public void testInstantiatePacket() {
        DRSUsageMonitorPacket drsPack;
        DRSUsageMonitorPacket drsPack2;
        byte array[];
        CustomByteBuffer buf;
        try
        {
            drsPack = createPacket();
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return;
        }
        buf = new CustomByteBuffer(1500);
        buf.putShort(drsPack.getComponentCode());
        buf.putShort(drsPack.getPacketVersion());
        drsPack.packCustomFields(buf);
        buf.rewind();

        /* Is this the intended design? */
        drsPack2 = (DRSUsageMonitorPacket) handler.instantiatePacket(buf);
        drsPack2.parseByteArray(buf.array());
        System.out.println("drsPack  = " + drsPack);
        System.out.println("drsPack2 = " + drsPack2);

	Assert.assertEquals("Component code should be " +
                            Short.toString(DRSUsageMonitorPacket.COMPONENT_CODE),
			    drsPack.getComponentCode(), 
                            DRSUsageMonitorPacket.COMPONENT_CODE);
	Assert.assertEquals("Component Mismatch",
			    drsPack.getComponentCode(),
			    drsPack2.getComponentCode());
	Assert.assertEquals("PacketVersion should be " +
                            Short.toString(DRSUsageMonitorPacket.PACKET_VERSION),
			    drsPack.getPacketVersion(), 
                            DRSUsageMonitorPacket.PACKET_VERSION);
	Assert.assertEquals("PacketVersion Mismatch",
			    drsPack.getPacketVersion(),
			    drsPack2.getPacketVersion());
        Assert.assertEquals("NumberOfFiles mismatch",
                            drsPack.getNumberOfFiles(),
                            drsPack2.getNumberOfFiles());
        Assert.assertEquals("NumberOfResources mismatch",
                            drsPack.getNumberOfResources(),
                            drsPack2.getNumberOfResources());
    }

    public void testDRSHandler() {
        DRSUsageMonitorPacket drsPack;
        DRSUsageMonitorPacket drsPack2;
        try
        {
            drsPack = createPacket();
            CustomByteBuffer buf = new CustomByteBuffer(1500);
            buf.putShort(drsPack.getComponentCode());
            buf.putShort(drsPack.getPacketVersion());
            drsPack.packCustomFields(buf);
            buf.rewind();

            /* Is this the intended design? */
            drsPack2 = (DRSUsageMonitorPacket) handler.instantiatePacket(buf);
            drsPack2.parseByteArray(buf.array());
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return;
        }
        handler.handlePacket(drsPack2);
    }
}
