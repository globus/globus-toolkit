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

// Used by the RFT service
import org.globus.transfer.reliable.service.usage.RFTUsageMonitorPacket;
// Used by the receiver
//import org.globus.usage.packets.RFTUsageMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.receiver.handlers.RFTPacketHandler;


public class RFTPacketHandlerTester extends TestCase {
    static private java.util.Random random = new java.util.Random();
    static private RFTPacketHandler handler = null;
    static private org.globus.usage.receiver.HandlerThread handlerThread = null;
    
    public RFTPacketHandlerTester(String name) {
	super(name);
    }

    public void setUp() throws Exception {
        String dburl = System.getProperty("dburl");

        if (dburl != null && !dburl.equals("${dburl}"))
        {
            java.util.Properties props = new java.util.Properties();

            props.put("database-driver", "org.postgresql.Driver");
            props.put("database-url", dburl);
            props.put("default-table", "unknown_packets");

            handlerThread = new  org.globus.usage.receiver.HandlerThread(
                    null, null, props);

            handler = new RFTPacketHandler(dburl, "rft_packets");
        }
    }

    private RFTUsageMonitorPacket createPacket()
            throws java.net.UnknownHostException
    {
        RFTUsageMonitorPacket rftPack = new RFTUsageMonitorPacket();
        java.util.Date now = new java.util.Date();

        try
        {
            rftPack.setHostIP(java.net.InetAddress.getLocalHost());
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return null;
        }
        rftPack.setNumberOfFiles(1);
        rftPack.setNumberOfBytes(2);
        rftPack.setNumberOfResources(3);
        rftPack.setResourceCreationTime(now);
        rftPack.setFactoryStartTime(now);
        rftPack.setRequestType(false);

        return rftPack;
    }

    /** Create a packet, turn it into a buffer, then call the RFT handler's
      * instantiatePacket method to create a copy of it, then compare the
      * packets.
      */
    public void testInstantiatePacket() {
        if (handler == null)
        {
            System.out.println("Skipping testInstantiatePacket");
            return;
        }
        RFTUsageMonitorPacket rftPack;
        org.globus.usage.packets.RFTUsageMonitorPacket rftPack2;
        byte array[];
        CustomByteBuffer buf;
        try
        {
            rftPack = createPacket();
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return;
        }
        buf = new CustomByteBuffer(1500);
        buf.putShort(rftPack.getComponentCode());
        buf.putShort(rftPack.getPacketVersion());
        rftPack.packCustomFields(buf);
        buf.rewind();

        /* Is this the intended design? */
        rftPack2 = (org.globus.usage.packets.RFTUsageMonitorPacket)
                handler.instantiatePacket(buf);
        rftPack2.parseByteArray(buf.array());
        System.out.println("rftPack  = " + rftPack);
        System.out.println("rftPack2 = " + rftPack2);

	Assert.assertEquals("Component code should be 5",
			    rftPack.getComponentCode(), 5);
	Assert.assertEquals("Component Mismatch",
			    rftPack.getComponentCode(),
			    rftPack2.getComponentCode());
        Assert.assertEquals("NumberOfFiles mismatch",
                            rftPack.getNumberOfFiles(),
                            rftPack2.getNumberOfFiles());
        Assert.assertEquals("NumberOfBytes mismatch",
                            rftPack.getNumberOfBytes(),
                            rftPack2.getNumberOfBytes());
        Assert.assertEquals("NumberOfResources mismatch",
                            rftPack.getNumberOfResources(),
                            rftPack2.getNumberOfResources());
        Assert.assertEquals("ResourceCreationTime mismatch",
                            rftPack.getResourceCreationTime(),
                            rftPack2.getResourceCreationTime());
        Assert.assertEquals("FactoryStartTime mismatch",
                            rftPack.getFactoryStartTime(),
                            rftPack2.getFactoryStartTime());
        Assert.assertEquals("RequestType mismatch",
                            rftPack.isTransfer(),
                            rftPack2.isTransfer());
    }

    public void testRFTHandler() {
        if (handler == null)
        {
            System.out.println("Skipping testRFTHandler");
            return;
        }
        RFTUsageMonitorPacket rftPack;
        org.globus.usage.packets.RFTUsageMonitorPacket rftPack2;
        try
        {
            rftPack = createPacket();
            CustomByteBuffer buf = new CustomByteBuffer(1500);
            buf.putShort(rftPack.getComponentCode());
            buf.putShort(rftPack.getPacketVersion());
            rftPack.packCustomFields(buf);
            buf.rewind();

            /* Is this the intended design? */
            rftPack2 = (org.globus.usage.packets.RFTUsageMonitorPacket)
                            handler.instantiatePacket(buf);
            rftPack2.parseByteArray(buf.array());
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return;
        }
        System.out.println("handler="+handler.toString());
        System.out.println("rftPack="+rftPack.toString());
        handler.handlePacket(rftPack2);
        // TODO query DB
    }
}
