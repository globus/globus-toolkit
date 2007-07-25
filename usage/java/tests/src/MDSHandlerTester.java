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

import org.globus.usage.packets.MDSAggregatorMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.receiver.handlers.MDSAggregatorPacketHandler;


public class MDSHandlerTester extends TestCase {
    static private java.util.Random random = new java.util.Random();
    static private MDSAggregatorPacketHandler handler = null;
    static private org.globus.usage.receiver.HandlerThread handlerThread = null;
    
    public MDSHandlerTester(String name) {
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

            handler = new MDSAggregatorPacketHandler(dburl, "mds_packets");
        }
    }

    private MDSAggregatorMonitorPacket createPacket()
            throws java.net.UnknownHostException
    {
        MDSAggregatorMonitorPacket mdsPack = new MDSAggregatorMonitorPacket();
        java.util.Date now = new java.util.Date();

        mdsPack.setLifetimeRegistrationCount(2);
        mdsPack.setCurrentRegistrantCount(1);
        mdsPack.setResourceCreationTime(now);
        mdsPack.setServiceName("TestService");
        try
        {
            mdsPack.setHostIP(java.net.InetAddress.getLocalHost());
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return null;
        }


        return mdsPack;
    }

    /** Create a packet, turn it into a buffer, then call the MDS handler's
      * instantiatePacket method to create a copy of it, then compare the
      * packets.
      */
    public void testInstantiatePacket() {
        if (handler == null)
        {
            System.out.println("Skipping testInstantiatePacket");
            return;
        }
        MDSAggregatorMonitorPacket mdsPack;
        MDSAggregatorMonitorPacket mdsPack2;
        byte array[];
        CustomByteBuffer buf;
        try
        {
            mdsPack = createPacket();
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return;
        }
        buf = new CustomByteBuffer(1500);
        buf.putShort(mdsPack.getComponentCode());
        buf.putShort(mdsPack.getPacketVersion());
        mdsPack.packCustomFields(buf);
        buf.rewind();

        /* Is this the intended design? */
        mdsPack2 = (MDSAggregatorMonitorPacket) handler.instantiatePacket(buf);
        mdsPack2.parseByteArray(buf.array());
        System.out.println("mdsPack  = " + mdsPack);
        System.out.println("mdsPack2 = " + mdsPack2);

        Assert.assertEquals("Component code should be 6",
                mdsPack.getComponentCode(), 6);
        Assert.assertEquals("Component code Mismatch",
                mdsPack.getComponentCode(), 
                mdsPack2.getComponentCode());
        Assert.assertEquals("LifetimeRegistrationCount Mismatch",
                mdsPack.getLifetimeRegistrationCount(),
                mdsPack2.getLifetimeRegistrationCount());
        Assert.assertEquals("CurrentRegistrantCount Mismatch",
                mdsPack.getCurrentRegistrantCount(),
                mdsPack2.getCurrentRegistrantCount());
        Assert.assertEquals("ResourceCreationTime Mismatch",
                mdsPack.getResourceCreationTime(),
                mdsPack2.getResourceCreationTime());
        /* Strings get padded to fixed length when packed */
        String sn1 = mdsPack.getServiceName();
        String sn2 = mdsPack2.getServiceName();

        Assert.assertEquals("ServiceName Mismatch",
                sn1,
                sn2.substring(0, sn1.length()));

    }

    public void testMDSHandler() {
        if (handler == null)
        {
            System.out.println("Skipping testMDSHandler");
            return;
        }
        MDSAggregatorMonitorPacket mdsPack;
        MDSAggregatorMonitorPacket mdsPack2;
        try
        {
            mdsPack = createPacket();
            CustomByteBuffer buf = new CustomByteBuffer(1500);
            buf.putShort(mdsPack.getComponentCode());
            buf.putShort(mdsPack.getPacketVersion());
            mdsPack.packCustomFields(buf);
            buf.rewind();

            /* Is this the intended design? */
            mdsPack2 = (MDSAggregatorMonitorPacket) handler.instantiatePacket(buf);
            mdsPack2.parseByteArray(buf.array());
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return;
        }
        System.out.println("handler="+handler.toString());
        System.out.println("mdsPack="+mdsPack.toString());
        handler.handlePacket(mdsPack2);
        // TODO query DB
    }
}
