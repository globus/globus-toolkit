package org.globus.usage;

import junit.framework.TestCase;
import junit.framework.Test;
import junit.framework.Assert;
import junit.framework.TestSuite;

import org.globus.usage.packets.PacketFieldParser;

public class PacketFieldParserTester extends TestCase {
    
    public PacketFieldParserTester(String name) {
	super(name);
    }
	
    public void testParsing() {
	String testString;
	PacketFieldParser parser;

	testString = "HOSTNAME=mayed.mcs.anl.gov START=20050225073026.426286 END=20050225073026.560613 VER=\"0.17 (gcc32dbg, 1108765962-1)\" BUFFER=16000 BLOCK=262144 NBYTES=504 STREAMS=1 STRIPES=1 TYPE=RETR CODE=226";
	parser = new PacketFieldParser(testString);

	
	Assert.assertEquals("Should be 11 fields", parser.countFields(), 11);
	Assert.assertEquals("hostname wrong", parser.getString("HOSTNAME"), "mayed.mcs.anl.gov");
	Assert.assertEquals("buffer wrong", parser.getInt("BUFFER"), 16000);
	Assert.assertEquals("block wrong", parser.getInt("BLOCK"), 262144);
	Assert.assertEquals("nbytes wrong", parser.getInt("NBYTES"), 504);
	Assert.assertEquals("streams wrong", parser.getInt("STREAMS"), 1);
	Assert.assertEquals("code wrong", parser.getInt("CODE"), 226);
	Assert.assertEquals("type wrong", parser.getString("TYPE"), "RETR");
	Assert.assertEquals("version wrong", parser.getString("VER"), "0.17 (gcc32dbg, 1108765962-1)");
	Assert.assertEquals("start wrong", parser.getDouble("START"), 20050225073026.426286);
	Assert.assertEquals("end wrong", parser.getDouble("END"), 20050225073026.560613);

    }

}
