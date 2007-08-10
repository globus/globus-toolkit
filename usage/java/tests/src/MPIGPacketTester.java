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
import java.sql.Timestamp;

import org.globus.usage.packets.MPIGMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;


public class MPIGPacketTester extends TestCase {
    
    public MPIGPacketTester(String name) {
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

    public void testPacket() {
        File f = new File("packets" + File.separator + "mpig");
        byte [] data = readPacket(f);

        CustomByteBuffer b = CustomByteBuffer.wrap(data);

        MPIGMonitorPacket pack = new MPIGMonitorPacket();
        pack.parseByteArray(b.array());

        Assert.assertEquals("tg-c059.uc.teragrid.org",
                            pack.getHostname());

        Assert.assertEquals("1.0.6",
                            pack.getMpichVer());

        Timestamp t = new Timestamp(((long) 1185941739) * 1000);
        t.setNanos(996472 * 1000);
        Assert.assertEquals(t, pack.getStartTimestamp());

        t  = new Timestamp(((long) 1185941740) * 1000);
        t.setNanos(15773 * 1000);
        Assert.assertEquals(t, pack.getEndTimestamp());

        Assert.assertEquals(2, pack.getNprocs());
        Assert.assertEquals(0, pack.getNbytes());
        Assert.assertEquals(3540, pack.getNbytesv());

        Assert.assertEquals(
            "AgAAADAAAAAGAAAAEAAAAAkAAAArAAAADQAAAAwA" +
            "AAAOAAAACgAAAA8AAAAMAAAAEAAAAAoAAAARAAAA" +
            "FAAAACQAAAAUAAAAJgAAAAYAAAAnAAAADAAAACkA" +
            "AAAFAAAAKgAAAB4AAAArAAAAAgAAACwAAAAKAAAA" +
            "MAAAACIAAAAyAAAAFgAAADQAAAAGAAAANQAAAEgA" +
            "AAA2AAAAEgAAADgAAAAeAAAAOwAAAAQAAAA8AAAA" +
            "DAAAAEEAAAASAAAASQAAAAIAAABMAAAABAAAAFAA" +
            "AAAQAAAAXwAAADAAAABgAAAADgAAAGQAAAASAAAA" +
            "cgAAAAIAAAB1AAAABAAAAHYAAAACAAAAfQAAAAIA" +
            "AAB+AAAAAgAAAI4AAAACAAAAmQAAAAwAAACoAAAA" +
            "BAAAALwAAABwAAAAvwAAAFkAAADIAAAABAAAAA==",
            pack.getFnmap());
    }
}
