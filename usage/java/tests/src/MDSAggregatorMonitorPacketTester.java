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

import org.globus.mds.aggregator.impl.MDSAggregatorMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;

public class MDSAggregatorMonitorPacketTester extends TestCase {
    
    public MDSAggregatorMonitorPacketTester(String name) {
	super(name);
    }

    public void testMDSAggregator() {
        MDSAggregatorMonitorPacket mdsPack;
        MDSAggregatorMonitorPacket mdsPack2;
        java.util.Date now = new java.util.Date();
        CustomByteBuffer buf = new CustomByteBuffer(1500);

        mdsPack = new MDSAggregatorMonitorPacket();
        mdsPack.setLifetimeRegistrationCount(2);
        Assert.assertEquals("setLifetimeRegistrationCount failed",
                            mdsPack.getLifetimeRegistrationCount(),
                            2);
        mdsPack.setCurrentRegistrantCount(1);
        Assert.assertEquals("setCurrentRegistrantCount failed",
                            mdsPack.getCurrentRegistrantCount(),
                            1);
        mdsPack.setResourceCreationTime(now);
        Assert.assertEquals("setResourceCreationTime",
                            mdsPack.getResourceCreationTime(),
                            now);
        mdsPack.setServiceName("TestService");
        Assert.assertEquals("setServiceName failed",
                            mdsPack.getServiceName(),
                            "TestService");
        try
        {
            mdsPack.setHostIP(java.net.InetAddress.getLocalHost());
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return;
        }
        mdsPack.packCustomFields(buf);

        buf.rewind();

        mdsPack2 = new MDSAggregatorMonitorPacket();
        mdsPack2.unpackCustomFields(buf);

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
}
