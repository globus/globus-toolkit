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

import org.globus.usage.packets.CWSMonitorPacketV2;
import org.globus.usage.packets.CustomByteBuffer;


public class CWSCorePacketV2Tester extends TestCase {
    
    public CWSCorePacketV2Tester(String name) {
	super(name);
    }

    protected byte[] readPacket(File f) {
        byte [] data = null;
        FileInputStream s = null;

        try {
            s = new FileInputStream(f);
            data = new byte[(int) f.length()];

            s.read(data);
        } catch (IOException ioe) {
            Assert.assertEquals(ioe, null);
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (IOException ioe) {
                    Assert.assertEquals(ioe, null);
                }
            }
        }
        return data;
    }

    public void testStartPacket() {
        File f = new File("packets" + File.separator + "cwscore2.start");
        byte [] data = readPacket(f);

        CustomByteBuffer b = CustomByteBuffer.wrap(data);

        CWSMonitorPacketV2 pack = new CWSMonitorPacketV2();
        pack.parseByteArray(b.array());

        Assert.assertEquals(pack.getId(), 25356);
        Assert.assertEquals(pack.getEvent(), CWSMonitorPacketV2.START_EVENT);
        Assert.assertEquals(pack.getServices(),
                            "NotificationConsumerService,SubscriptionManagerService");
    }

    public void testStopPacket() {
        File f = new File("packets" + File.separator + "cwscore2.stop");
        byte [] data = readPacket(f);

        CustomByteBuffer b = CustomByteBuffer.wrap(data);

        CWSMonitorPacketV2 pack = new CWSMonitorPacketV2();
        pack.parseByteArray(b.array());

        Assert.assertEquals(pack.getId(), 25356);
        Assert.assertEquals(pack.getEvent(), CWSMonitorPacketV2.STOP_EVENT);
    }
}
