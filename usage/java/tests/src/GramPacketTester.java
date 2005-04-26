/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */



package org.globus.usage;

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
