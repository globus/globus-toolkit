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

import org.globus.usage.packets.RFTUsageMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;

public class RFTUsageMonitorPacketTester extends TestCase {
    
    public RFTUsageMonitorPacketTester(String name) {
	super(name);
    }

    public void testRFT() {
        RFTUsageMonitorPacket pack1;
        RFTUsageMonitorPacket pack2;
        CustomByteBuffer buf = new CustomByteBuffer(1500);
        java.util.Date now = new java.util.Date();

        pack1 = new RFTUsageMonitorPacket();
        try
        {
            pack1.setHostIP(java.net.InetAddress.getLocalHost());
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return;
        }
        pack1.setNumberOfFiles(1);
        Assert.assertEquals("setNumberOfFiles failed",
                            pack1.getNumberOfFiles(),
                            1);
        pack1.setNumberOfBytes(2);
        Assert.assertEquals("setNumberOfBytes failed",
                            pack1.getNumberOfBytes(),
                            2);
        pack1.setNumberOfResources(3);
        Assert.assertEquals("setNumberOfResources failed",
                            pack1.getNumberOfResources(),
                            3);
        pack1.setResourceCreationTime(now);
        Assert.assertEquals("setResourceCreationTime failed",
                            pack1.getResourceCreationTime(),
                            now);
        pack1.setFactoryStartTime(now);
        Assert.assertEquals("setFactoryStartTime failed",
                            pack1.getFactoryStartTime(),
                            now);
        pack1.setRequestType(pack1.TRANSFER);
        Assert.assertTrue("setRequestType failed",
                            pack1.isTransfer());

        pack1.packCustomFields(buf);
        buf.rewind();

        pack2 = new RFTUsageMonitorPacket();
        pack2.unpackCustomFields(buf);

	Assert.assertEquals("Component code should be 5",
			    pack1.getComponentCode(), 5);
	Assert.assertEquals("Component Mismatch",
			    pack1.getComponentCode(),
			    pack2.getComponentCode());
        Assert.assertEquals("NumberOfFiles mismatch",
                            pack1.getNumberOfFiles(),
                            pack2.getNumberOfFiles());
        Assert.assertEquals("NumberOfBytes mismatch",
                            pack1.getNumberOfBytes(),
                            pack2.getNumberOfBytes());
        Assert.assertEquals("NumberOfResources mismatch",
                            pack1.getNumberOfResources(),
                            pack2.getNumberOfResources());
        Assert.assertEquals("ResourceCreationTime mismatch",
                            pack1.getResourceCreationTime(),
                            pack2.getResourceCreationTime());
        Assert.assertEquals("FactoryStartTime mismatch",
                            pack1.getFactoryStartTime(),
                            pack2.getFactoryStartTime());
        Assert.assertEquals("RequestType mismatch",
                            pack1.isTransfer(),
                            pack2.isTransfer());
    }
}
