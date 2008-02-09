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

import org.globus.wsrf.utils.Version;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.ContainerUsagePacketV3;
import org.globus.usage.receiver.handlers.JavaCorePacketHandlerV3;

public class JWSCorePacketHandlerV3Tester extends TestCase 
{
    static private JavaCorePacketHandlerV3 handler = null;    
    
    public JWSCorePacketHandlerV3Tester(String name) {
	super(name);
    }

    public void setUp() throws Exception {
        String dburl = System.getProperty("dburl");

        java.util.Properties props = new java.util.Properties();

        handler = new JavaCorePacketHandlerV3(props);
    }

    private ContainerUsagePacketV3 createPacket()
            throws java.net.UnknownHostException
    {
        ContainerUsagePacketV3 pack =
            new ContainerUsagePacketV3(ContainerUsagePacketV3.UPDATE_EVENT);
        
        pack.setServiceList(JWSCorePacketV3Tester.serviceList);
        pack.setContainerID(JWSCorePacketV3Tester.containerID);
        pack.setContainerType(ContainerUsagePacketV3.STANDALONE_CONTAINER);
        pack.setPortNumber(JWSCorePacketV3Tester.portNumber);
        pack.setUptime(JWSCorePacketV3Tester.uptime);
        pack.setThreadPoolSize(JWSCorePacketV3Tester.threadPoolSize);
        pack.setCurrentThreadCount(JWSCorePacketV3Tester.threadCount);
        pack.setThreadsHighWaterMark(JWSCorePacketV3Tester.threadsHighWaterMark);
        pack.setMaxThreadCount(JWSCorePacketV3Tester.maxThreads);
        pack.setServiceRequestCount(JWSCorePacketV3Tester.serviceRequestCount);
        pack.setVersion(
            Version.getMajor(),Version.getMinor(),Version.getMicro());
        try
        {
            pack.setHostIP(java.net.InetAddress.getLocalHost());
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return null;
        }

        return pack;
    }

    /** Create a packet, turn it into a buffer, then call the handler's
      * instantiatePacket method to create a copy of it, then compare the
      * packets.
      */
    public void testInstantiatePacket() 
    {
        ContainerUsagePacketV3 pack;
        ContainerUsagePacketV3 pack2;
        byte array[];
        CustomByteBuffer buf;
        try
        {
            pack = createPacket();
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return;
        }
        buf = new CustomByteBuffer(1500);
        buf.putShort(pack.getComponentCode());
        buf.putShort(pack.getPacketVersion());
        pack.packCustomFields(buf);
        buf.rewind();

        pack2 = (ContainerUsagePacketV3) handler.instantiatePacket(buf);
        pack2.parseByteArray(buf.array());
        System.out.println("pack  = " + pack);
        System.out.println("pack2 = " + pack2);

        Assert.assertEquals("Component code should be " +
                            Short.toString(ContainerUsagePacketV3.COMPONENT_CODE),
                            pack.getComponentCode(),
                            ContainerUsagePacketV3.COMPONENT_CODE);
        Assert.assertEquals("Component Mismatch",
                            pack.getComponentCode(),
                            pack2.getComponentCode());
        Assert.assertEquals("PacketVersion should be " +
                            Short.toString(ContainerUsagePacketV3.PACKET_VERSION),
                            pack.getPacketVersion(), 
                            ContainerUsagePacketV3.PACKET_VERSION);
        Assert.assertEquals("PacketVersion Mismatch",
                            pack.getPacketVersion(),
                            pack2.getPacketVersion());
        Assert.assertEquals("PortNumber Mismatch",
                            pack.getPortNumber(),
                            pack2.getPortNumber());     
        Assert.assertEquals("Uptime Mismatch",
                            pack.getUptime(),
                            pack2.getUptime());          
        Assert.assertEquals("ThreadPoolSize Mismatch",
                            pack.getThreadPoolSize(),
                            pack2.getThreadPoolSize());  
        Assert.assertEquals("CurrentThreadCount Mismatch",
                            pack.getCurrentThreadCount(),
                            pack2.getCurrentThreadCount());  
        Assert.assertEquals("ThreadsHighWaterMark Mismatch",
                            pack.getThreadsHighWaterMark(),
                            pack2.getThreadsHighWaterMark());  
        Assert.assertEquals("MaxThreadCount Mismatch",
                            pack.getMaxThreadCount(),
                            pack2.getMaxThreadCount());  
        Assert.assertEquals("ServiceRequestCount Mismatch",
                            pack.getServiceRequestCount(),
                            pack2.getServiceRequestCount());  
        Assert.assertEquals("MajorVersion Mismatch",
                            pack.getMajorVersion(),
                            pack2.getMajorVersion());  
        Assert.assertEquals("MinorVersion Mismatch",
                            pack.getMinorVersion(),
                            pack2.getMinorVersion());  
        Assert.assertEquals("MicroVersion Mismatch",
                            pack.getMicroVersion(),
                            pack2.getMicroVersion());           
         
        /* Strings get padded to fixed length when packed */
        String s1 = pack.getServiceList();
        String s2 = pack2.getServiceList();

        Assert.assertEquals("ServiceList mismatch", s1, s2);        
    }

    public void testHandler() {
        ContainerUsagePacketV3 pack;
        ContainerUsagePacketV3 pack2;
        try
        {
            pack = createPacket();
            CustomByteBuffer buf = new CustomByteBuffer(1500);
            buf.putShort(pack.getComponentCode());
            buf.putShort(pack.getPacketVersion());
            pack.packCustomFields(buf);
            buf.rewind();

            pack2 = (ContainerUsagePacketV3) handler.instantiatePacket(buf);
            pack2.parseByteArray(buf.array());
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return;
        }
        handler.handlePacket(pack2);
    }
}
