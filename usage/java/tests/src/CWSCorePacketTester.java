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

import org.globus.usage.packets.CWSMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;


public class CWSCorePacketTester extends TestCase {
    
    public CWSCorePacketTester(String name) {
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
        File f = new File("packets" + File.separator + "cwscore");
        byte [] data = readPacket(f);

        CustomByteBuffer b = CustomByteBuffer.wrap(data);

        CWSMonitorPacket pack = new CWSMonitorPacket();
        pack.parseByteArray(b.array());
    }
}
