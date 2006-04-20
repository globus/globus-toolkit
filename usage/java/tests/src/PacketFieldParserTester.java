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

import java.util.Calendar;

import org.globus.usage.packets.PacketFieldParser;
import org.globus.usage.packets.CustomByteBuffer;

public class PacketFieldParserTester extends TestCase {
    
    public PacketFieldParserTester(String name) {
	super(name);
    }

    public void testCDate() {

	/*Real captured C WS Core packets.  Dates are in 4-byte c/unix time_t format, supposedly (that's an unsigned int of seconds since midnight Jan 1 1970.)*/

	byte[] packet1bytes = {4, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 66, 90, 2, -83, 72, 79, 83, 84, 78, 65, 77, 69, 61, 110, 105, 109, 114, 111, 100, 46, 105, 115, 105, 46, 101, 100, 117};

	byte[] packet2bytes = {4, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 66, 90, 2, -74, 72, 79, 83, 84, 78, 65, 77, 69, 61, 110, 105, 109, 114, 111, 100, 46, 105, 115, 105, 46, 101, 100, 117}; 

	byte[] packet3bytes = {4, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 66, 90, 2, -60, 72, 79, 83, 84, 78, 65, 77, 69, 61, 110, 105, 109, 114, 111, 100, 46, 105, 115, 105, 46, 101, 100, 117};

	byte[] ipBytes = new byte[16];
	
	CustomByteBuffer buf;

	buf = CustomByteBuffer.wrap(packet1bytes);

	Assert.assertEquals("First short should be 4",buf.getShort(), 4);
	Assert.assertEquals("Second short should be 4",buf.getShort(), 4);
	buf.get(ipBytes);


	Calendar epoch = Calendar.getInstance();
        int secondsSinceEpoch = buf.getIntBigEndian();
        epoch.set(1970, 0, 0, 0, 0, 0);
        epoch.set(Calendar.MILLISECOND, 0);
        epoch.add(Calendar.SECOND, secondsSinceEpoch);
        if (secondsSinceEpoch < 0 ) {
            epoch.add(Calendar.SECOND, Integer.MAX_VALUE);
        }
        System.out.println("Packet 1: Seconds since epoch = "+secondsSinceEpoch);
        System.out.println("--> "+epoch.getTime());


	String stringyPart = new String(buf.getRemainingBytes());
	System.out.println("TestCDate: stringyPart: "+stringyPart);


	buf = CustomByteBuffer.wrap(packet2bytes);
	Assert.assertEquals("First short should be 4",buf.getShort(), 4);
	Assert.assertEquals("Second short should be 4",buf.getShort(), 4);
	buf.get(ipBytes);
	epoch = Calendar.getInstance();
        secondsSinceEpoch = buf.getIntBigEndian();
        epoch.set(1970, 0, 0, 0, 0, 0);
        epoch.set(Calendar.MILLISECOND, 0);
        epoch.add(Calendar.SECOND, secondsSinceEpoch);
        if (secondsSinceEpoch < 0 ) {
            epoch.add(Calendar.SECOND, Integer.MAX_VALUE);
        }
        System.out.println("Packet 2: Seconds since epoch = "+secondsSinceEpoch);
        System.out.println("--> "+epoch.getTime());
	stringyPart = new String(buf.getRemainingBytes());
	System.out.println("TestCDate: stringyPart: "+stringyPart);


	buf = CustomByteBuffer.wrap(packet3bytes);
	Assert.assertEquals("First short should be 4",buf.getShort(), 4);
	Assert.assertEquals("Second short should be 4",buf.getShort(), 4);
	buf.get(ipBytes);
	epoch = Calendar.getInstance();
        secondsSinceEpoch = buf.getIntBigEndian();
        epoch.set(1970, 0, 0, 0, 0, 0);
        epoch.set(Calendar.MILLISECOND, 0);
        epoch.add(Calendar.SECOND, secondsSinceEpoch);
        if (secondsSinceEpoch < 0 ) {
            epoch.add(Calendar.SECOND, Integer.MAX_VALUE);
        }
        System.out.println("Packet 3: Seconds since epoch = "+secondsSinceEpoch);
        System.out.println("--> "+epoch.getTime());


	stringyPart = new String(buf.getRemainingBytes());
	System.out.println("TestCDate: stringyPart: "+stringyPart);

	
    }
	
    public void testParsing() {
	String testString;
	PacketFieldParser parser;

	testString = "HOSTNAME=mayed.mcs.anl.gov START=20050225073026.426286 END=20050225073026.560613 VER=\"0.17 (gcc32dbg, 1108765962-1)\" BUFFER=16000 BLOCK=262144 NBYTES=504 STREAMS=1 STRIPES=1 TYPE=RETR CODE=226";
	parser = new PacketFieldParser(testString);

	try {
	    Assert.assertEquals("Should be 11 fields", parser.countFields(), 11);
	    Assert.assertEquals("hostname wrong", parser.getString("HOSTNAME"), "mayed.mcs.anl.gov");
	    Assert.assertEquals("buffer wrong", parser.getInt("BUFFER"), 16000);
	    Assert.assertEquals("block wrong", parser.getInt("BLOCK"), 262144);
	    Assert.assertEquals("nbytes wrong", parser.getInt("NBYTES"), 504);
	    Assert.assertEquals("streams wrong", parser.getInt("STREAMS"), 1);
	    Assert.assertEquals("code wrong", parser.getInt("CODE"), 226);
	    Assert.assertEquals("type wrong", parser.getString("TYPE"), "RETR");
	    Assert.assertEquals("version wrong", parser.getString("VER"), "0.17 (gcc32dbg, 1108765962-1)");
	    Assert.assertTrue("start wrong", (parser.getDouble("START") == 20050225073026.426286));
	    Assert.assertTrue("end wrong", (parser.getDouble("END") == 20050225073026.560613));
	}
	catch (Exception e) {
	    Assert.fail("Exception: "+e.getMessage());
	}
    }

}
