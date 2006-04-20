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

import org.globus.usage.packets.GramUsageMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;

public class GramPacketTester extends TestCase {
    
    GramUsageMonitorPacket gramPack;

    public GramPacketTester(String name) {
	super(name);
    }

    protected void setUp() {
	byte[] realGramBytes = {1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, -128, 9, 72, 104, -86, 33, 72, 48, 3, 1, 0, 0, 70, 111, 114, 107, 91, 67, 64, 50, 56, 99, 97, 48, 55, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	gramPack = new GramUsageMonitorPacket();
	try {
	    gramPack.parseByteArray(realGramBytes);
	}
	catch (Exception e) {
	    Assert.fail(e.getMessage());
	}
	
    }


    public void testGram() {

	Assert.assertEquals("Component codeshould be 1",
			    gramPack.getComponentCode(), 1);
    }
}
