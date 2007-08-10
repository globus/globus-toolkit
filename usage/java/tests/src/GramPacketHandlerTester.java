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

import org.globus.exec.service.usage.GramUsageMonitorPacket;
//import org.globus.usage.packets.GramUsageMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.receiver.handlers.GRAMPacketHandler;


public class GramPacketHandlerTester extends TestCase {
    static private java.util.Random random = new java.util.Random();
    static private GRAMPacketHandler handler = null;
    
    public GramPacketHandlerTester(String name) {
	super(name);
    }

    public void setUp() throws Exception {
        String dburl = System.getProperty("dburl");

        java.util.Properties props = new java.util.Properties();

        handler = new GRAMPacketHandler(props);
    }

    private GramUsageMonitorPacket createPacket()
            throws java.net.UnknownHostException
    {
        String testRM = "Test" + Integer.toString(random.nextInt());
        GramUsageMonitorPacket gramPack;
        java.util.Date now = new java.util.Date();

        System.out.println("Using " + testRM);

        gramPack = new GramUsageMonitorPacket();
        gramPack.setCreationTime(now);
        gramPack.setLocalResourceManager(testRM);
        gramPack.setJobCredentialEndpointUsed(true);
        gramPack.setFileStageInUsed(false);
        gramPack.setFileStageOutUsed(true);
        gramPack.setFileCleanUpUsed(false);
        gramPack.setCleanUpHoldUsed(true);
        gramPack.setJobType(org.globus.exec.generated.JobTypeEnumeration.single);
        gramPack.setGt2ErrorCode(2);
        try {
        gramPack.setFaultClass(Class.forName("org.globus.exec.generated.FaultType"));
        } catch (Exception e) {;}

        gramPack.setHostIP(java.net.InetAddress.getLocalHost());

        return gramPack;
    }

    /** Create a packet, turn it into a buffer, then call the GRAM handler's
      * instantiatePacket method to create a copy of it, then compare the
      * packets.
      */
    public void testInstantiatePacket() {
        String testRM = "Test" + Integer.toString(random.nextInt());
        GramUsageMonitorPacket gramPack;
        org.globus.usage.packets.GramUsageMonitorPacket gramPack2;
        //GramUsageMonitorPacket gramPack2;
        byte array[];
        CustomByteBuffer buf;
        try
        {
            gramPack = createPacket();
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return;
        }
        buf = new CustomByteBuffer(1500);
        buf.putShort(gramPack.getComponentCode());
        buf.putShort(gramPack.getPacketVersion());
        gramPack.packCustomFields(buf);
        buf.rewind();

        /* Is this the intended design? */
        gramPack2 = (org.globus.usage.packets.GramUsageMonitorPacket)
                handler.instantiatePacket(buf);
        gramPack2.parseByteArray(buf.array());
        System.out.println("gramPack  = " + gramPack);
        System.out.println("gramPack2 = " + gramPack2);

        Assert.assertEquals("Component codeshould be 1",
                            gramPack.getComponentCode(), 1);
        Assert.assertEquals(gramPack.getComponentCode(),
                            gramPack2.getComponentCode());
        Assert.assertEquals(gramPack.getPacketVersion(),
                            gramPack2.getPacketVersion());
        Assert.assertEquals(gramPack.getCreationTime(),
                            gramPack2.getCreationTime());

        /* Strings get padded to fixed length when packed */
        String rm1 = gramPack.getLocalResourceManager();
        String rm2 = gramPack2.getLocalResourceManager();
        System.out.println(rm1);
        System.out.println(rm2);

        Assert.assertEquals("Local Resource Manager Mismatch",
                rm1,
                rm2.substring(0, rm1.length()));
        
        try {
            Byte b = (Byte) invokePrivateStaticMethod(GramUsageMonitorPacket.class,
                                      GramUsageMonitorPacket.class,
                                      "jobTypeEnumerationToByte",
                                      new Class [] {
                                          org.globus.exec.generated.JobTypeEnumeration.class
                                      },
                                      new Object [] {
                                          gramPack.getJobType()
                                      });
            Assert.assertEquals("JobType Mismatch",
                                b.byteValue(),
                                gramPack2.getJobType());
        } catch (Exception e) {
            Assert.assertEquals(e, null);

        }

        Assert.assertEquals("Gt2ErrorCode Mismatch",
                            gramPack.getGt2ErrorCode(),
                            gramPack2.getGt2ErrorCode());

        try {
            Byte b = (Byte) invokePrivateStaticMethod(
                            GramUsageMonitorPacket.class,
                            GramUsageMonitorPacket.class,
                            "faultClassToByte",
                            new Class [] {
                                Class.class
                            },
                            new Object [] {
                                gramPack.getFaultClass()
                            });

            Assert.assertEquals("FaultClass Mismatch",
                                b.byteValue(),
                                gramPack2.getFaultClass());
        } catch (Exception e) {
            Assert.assertEquals(e, null);
        }
        Assert.assertEquals("jobCredentialEndpointUsed mismatch",
                            gramPack.getJobCredentialEndpointUsed(),
                            gramPack2.getJobCredentialEndpointUsed());
        Assert.assertEquals("FileStageInUsed Mismatch",
                            gramPack.isFileStageInUsed(),
                            gramPack2.isFileStageInUsed());
        Assert.assertEquals("FileStageOut Mismatch",
                            gramPack.isFileStageOutUsed(),
                            gramPack2.isFileStageOutUsed());
        Assert.assertEquals("FileCleanUpUsed Mismatch",
                            gramPack.isFileCleanUpUsed(),
                            gramPack2.isFileCleanUpUsed());
        Assert.assertEquals("CleanUpHoldUsed Mismatch",
                            gramPack.isCleanUpHoldUsed(),
                            gramPack2.isCleanUpHoldUsed());
    }

    public void testGramHandler() {
        GramUsageMonitorPacket gramPack;
        org.globus.usage.packets.GramUsageMonitorPacket gramPack2;
        try
        {
            gramPack = createPacket();
            CustomByteBuffer buf = new CustomByteBuffer(1500);
            buf.putShort(gramPack.getComponentCode());
            buf.putShort(gramPack.getPacketVersion());
            gramPack.packCustomFields(buf);
            buf.rewind();

            /* Is this the intended design to instantiate and parse in separate steps? */
            gramPack2 = (org.globus.usage.packets.GramUsageMonitorPacket)
                            handler.instantiatePacket(buf);
            gramPack2.parseByteArray(buf.array());
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return;
        }
        handler.handlePacket(gramPack2);
    }
    static Object invokePrivateStaticMethod(Class targetClass, Object concreteObject,
                                            String methodName,
                                            Class[] argClasses, Object [] argObjects)
    throws Exception
    {
        Method method;
        Object returnObject;

        method = targetClass.getDeclaredMethod(methodName, argClasses);
        method.setAccessible(true);
        returnObject = method.invoke(concreteObject, argObjects);
        return returnObject;
    }
}
