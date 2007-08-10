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

import org.globus.usage.packets.DRSUsageMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;

public class DRSUsageMonitorPacketTester extends TestCase {
    
    public DRSUsageMonitorPacketTester(String name) {
	super(name);
    }

    public void testDRS() {
        DRSUsageMonitorPacket pack1;
        DRSUsageMonitorPacket pack2;
        CustomByteBuffer buf = new CustomByteBuffer(1500);
        java.util.Date now = new java.util.Date();

        pack1 = new DRSUsageMonitorPacket();
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
        pack1.setNumberOfResources(3);
        Assert.assertEquals("setNumberOfResources failed",
                            pack1.getNumberOfResources(),
                            3);

        pack1.packCustomFields(buf);
        buf.rewind();

        pack2 = new DRSUsageMonitorPacket();
        pack2.unpackCustomFields(buf);

	Assert.assertEquals("Component code should be " +
                            Short.toString(DRSUsageMonitorPacket.COMPONENT_CODE),
			    pack1.getComponentCode(), 
                            DRSUsageMonitorPacket.COMPONENT_CODE);
	Assert.assertEquals("Component Mismatch",
			    pack1.getComponentCode(),
			    pack2.getComponentCode());
	Assert.assertEquals("PacketVersion code should be " +
                            Short.toString(DRSUsageMonitorPacket.PACKET_VERSION),
			    pack1.getPacketVersion(), 
                            DRSUsageMonitorPacket.PACKET_VERSION);
	Assert.assertEquals("PacketVersion mismatch",
			    pack1.getPacketVersion(), 
			    pack2.getPacketVersion());
        Assert.assertEquals("NumberOfFiles mismatch",
                            pack1.getNumberOfFiles(),
                            pack2.getNumberOfFiles());
        Assert.assertEquals("NumberOfResources mismatch",
                            pack1.getNumberOfResources(),
                            pack2.getNumberOfResources());
    }
}
