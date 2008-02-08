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
import org.globus.wsrf.container.usage.ContainerUsagePacketV3;
import org.globus.usage.packets.CustomByteBuffer;

public class JWSCorePacketV3Tester extends TestCase 
{
    public static String serviceList = "a,b,c,d";
    public static int containerID = 42;
    public static int portNumber = 8443;
    public static int uptime = 298372345;
    public static short threadPoolSize = 2;
    public static short threadCount = 12;
    public static short threadsHighWaterMark = 10;
    public static short maxThreads = 20;
    public static int serviceRequestCount = 826523;   
    
    public JWSCorePacketV3Tester(String name) {
	super(name);
    }
    
    public static String getJvmInfo() {
        StringBuffer buf = 
            new StringBuffer(System.getProperty("java.version") + " " + 
                             System.getProperty("java.vendor"));
        buf.setLength(ContainerUsagePacketV3.JVM_INFO_LEN);
        return buf.toString();
    }
    public void testStartPacket() {
        this.runPacketTest(ContainerUsagePacketV3.START_EVENT);
    }

    public void testStopPacket() {
        this.runPacketTest(ContainerUsagePacketV3.STOP_EVENT);
    }
    
    public void testUpdatePacket() {
        this.runPacketTest(ContainerUsagePacketV3.UPDATE_EVENT);    
    }      
        
    private void runPacketTest(short eventType) 
    {
        CustomByteBuffer buf = new CustomByteBuffer(1500);        
        ContainerUsagePacketV3 pack = new ContainerUsagePacketV3(eventType);
        if (eventType == ContainerUsagePacketV3.START_EVENT) {    
            pack.setJvmInfo(getJvmInfo());
            Assert.assertEquals("setJvmInfo failed",
                                pack.getJvmInfo(),
                                getJvmInfo()); 
        }           
        pack.setServiceList(serviceList);
        Assert.assertEquals("setServiceList failed",
                            pack.getServiceList(),
                            serviceList);
        pack.setContainerID(containerID);
        Assert.assertEquals("setContainerID failed",
                            pack.getContainerID(),
                            containerID);
        pack.setContainerType(ContainerUsagePacketV3.STANDALONE_CONTAINER);
        Assert.assertEquals("setContainerType failed",
                            pack.getContainerType(),
                            ContainerUsagePacketV3.STANDALONE_CONTAINER);           
        pack.setPortNumber(portNumber);
        Assert.assertEquals("setPortNumber failed",
                            pack.getPortNumber(),
                            portNumber);        
        pack.setUptime(uptime);
        Assert.assertEquals("setUptime failed",
                            pack.getUptime(),
                            uptime);    
        pack.setThreadPoolSize(threadPoolSize);
        Assert.assertEquals("setThreadPoolSize failed",
                            pack.getThreadPoolSize(),
                            threadPoolSize);
        pack.setCurrentThreadCount(threadCount);
        Assert.assertEquals("setCurrentThreadCount failed",
                            pack.getCurrentThreadCount(),
                            threadCount);        
        pack.setThreadsHighWaterMark(threadsHighWaterMark);
        Assert.assertEquals("setThreadsHighWaterMark failed",
                            pack.getThreadsHighWaterMark(),
                            threadsHighWaterMark);
        pack.setMaxThreadCount(maxThreads);
        Assert.assertEquals("setMaxThreadCount failed",
                            pack.getMaxThreadCount(),
                            maxThreads);
        pack.setServiceRequestCount(serviceRequestCount);
        Assert.assertEquals("setServiceRequestCount failed",
                            pack.getServiceRequestCount(),
                            serviceRequestCount);
        pack.setVersion(Version.getMajor(),
                        Version.getMinor(),
                        Version.getMicro());
        Assert.assertEquals("setVersion (Major) failed",
                            pack.getMajorVersion(),
                            Version.getMajor());
        Assert.assertEquals("setVersion (Minor) failed",
                            pack.getMinorVersion(),
                            Version.getMinor());
        Assert.assertEquals("setVersion (Micro) failed",
                            pack.getMicroVersion(),
                            Version.getMicro());                        
        try
        {
            pack.setHostIP(java.net.InetAddress.getLocalHost());
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return;
        }
        pack.packCustomFields(buf);

        buf.rewind();

        ContainerUsagePacketV3 pack2 = new ContainerUsagePacketV3(eventType);
        pack2.unpackCustomFields(buf);
        
        System.out.println("pack  = " + pack);
        System.out.println("pack2 = " + pack2);
        
        Assert.assertEquals("Component code should be 3",
                            pack.getComponentCode(), 3);
        Assert.assertEquals("Container ID Mismatch",
                            pack.getContainerID(),
                            pack2.getContainerID());
        Assert.assertEquals("EventType Mismatch",
                            pack.getEventType(),
                            pack2.getEventType());
        Assert.assertEquals("ContainerType Mismatch",
                            pack.getContainerType(),
                            pack2.getContainerType());        
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
        
        if (eventType == ContainerUsagePacketV3.START_EVENT) {           
            s1 = pack.getJvmInfo();
            s2 = pack2.getJvmInfo();
            Assert.assertEquals("JVMInfoString mismatch", s1, s2);        
        }
    }
}
