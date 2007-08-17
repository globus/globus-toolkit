/*
 * Copyright 1999-2007 University of Chicago
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

import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.IOException;

import org.globus.usage.packets.OGSADAIMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;


public class OGSADAIPacketTester extends TestCase {
    
    public OGSADAIPacketTester(String name) {
	super(name);
    }

    OGSADAIMonitorPacket createPacket() {
        OGSADAIMonitorPacket packet = new OGSADAIMonitorPacket();

        packet.setCurrentActivity("Foo");

        return packet;
    }


    public void testPacket() {
        OGSADAIMonitorPacket packet;

        packet = createPacket();

        Assert.assertEquals(packet.getCurrentActivity(), "Foo");

        CustomByteBuffer buf = new CustomByteBuffer(1500);
        packet.packCustomFields(buf);
        buf.rewind();
    }

    public void testPacketPack() {
        OGSADAIMonitorPacket packet = createPacket();
        CustomByteBuffer buf = new CustomByteBuffer(1500);

        packet.packCustomFields(buf);
        buf.rewind();

        OGSADAIMonitorPacket packet2 = new OGSADAIMonitorPacket();
        packet2.unpackCustomFields(buf);

        Assert.assertEquals(10, packet2.getComponentCode());
        Assert.assertEquals(1, packet2.getPacketVersion());
        Assert.assertEquals(packet.getCurrentActivity(),
                            packet2.getCurrentActivity());
    }
}
