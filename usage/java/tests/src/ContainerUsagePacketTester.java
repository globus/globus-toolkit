
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

import org.globus.wsrf.container.usage.ContainerUsageBasePacket;
import org.globus.wsrf.container.usage.ContainerUsageStartPacket;
import org.globus.wsrf.container.usage.ContainerUsageStopPacket;
import org.globus.usage.packets.CustomByteBuffer;

public class ContainerUsagePacketTester extends TestCase {
    static String serviceList = "a,b,c,d";
    static int containerID = 42;
    
    public ContainerUsagePacketTester(String name) {
	super(name);
    }

    public void testStartPacket() {
        ContainerUsageStartPacket pack;
        ContainerUsageStartPacket pack2;

        CustomByteBuffer buf = new CustomByteBuffer(1500);

        pack = new ContainerUsageStartPacket();
        pack.setServiceList(serviceList);
        Assert.assertEquals("setServiceList failed",
                            pack.getServiceList(),
                            serviceList);
        pack.setContainerID(containerID);
        Assert.assertEquals("setContainerID failed",
                            pack.getContainerID(),
                            containerID);
        pack.setContainerType(ContainerUsageBasePacket.STANDALONE_CONTAINER);
        Assert.assertEquals("setContainerType failed",
                            pack.getContainerType(),
                            ContainerUsageBasePacket.STANDALONE_CONTAINER);
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

        pack2 = new ContainerUsageStartPacket();
        pack2.unpackCustomFields(buf);

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

        /* Strings get padded to fixed length when packed */
        String s1 = pack.getServiceList();
        String s2 = pack2.getServiceList();

        Assert.assertEquals("ServiceList mismatch",
                s1,
                s2);
    }

    public void testStopPacket() {
        ContainerUsageStopPacket pack;
        ContainerUsageStopPacket pack2;
        CustomByteBuffer buf = new CustomByteBuffer(1500);

        pack = new ContainerUsageStopPacket();
        pack.setContainerID(containerID);
        Assert.assertEquals("setContainerID failed",
                            pack.getContainerID(),
                            containerID);
        pack.setContainerType(ContainerUsageBasePacket.STANDALONE_CONTAINER);
        Assert.assertEquals("setContainerType failed",
                            pack.getContainerType(),
                            ContainerUsageBasePacket.STANDALONE_CONTAINER);
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

        pack2 = new ContainerUsageStopPacket();
        pack2.unpackCustomFields(buf);

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
    }
}
