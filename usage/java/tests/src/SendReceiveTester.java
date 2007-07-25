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
import java.util.Date;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.SocketException;
import java.io.IOException;
import java.sql.SQLException;

import org.globus.usage.packets.*;
import org.globus.usage.packets.samples.ExampleGFTPSender;
import org.globus.usage.receiver.*;
import org.globus.usage.receiver.samples.ExampleReceiver;
import org.globus.usage.receiver.handlers.*;

public class SendReceiveTester extends TestCase {
    static final int portNum = 4810;
	
    static final String dbdriver = "org.postgresql.Driver";
    static final String dbURL = "database-url = jdbc:postgresql://mayed.mcs.anl.gov/guss?user=jdicarlo&password=abcdefg";
    static final int buffersize = 128;
    static final String table = "unknown_packets";

    ExampleGFTPSender sender = null;
    Receiver receiver = null;


    public SendReceiveTester(String name) {
	super(name);
    }

    protected void setUp() {
	
	try {
	    sender = new ExampleGFTPSender(InetAddress.getByName("localhost"),portNum);
	    receiver = new Receiver(portNum, dbdriver, dbURL, table, buffersize);

	}
	catch (SocketException se) {
	    System.err.println("Socket error when trying to start sender.");
	}
	catch (UnknownHostException uhe) {
	    System.err.println("I'm confused about localhost's address.");
	}
	catch (IOException ioe) {
	    System.err.println("Error when trying to start receiver");
	}
    }

    protected void tearDown() {
	sender.shutDown();
	receiver.shutDown();
    }

    public void testSendReceive() {
	IPTimeMonitorPacket outgoing;
	UsageMonitorPacket incoming;
	InetAddress[] listOAddress;
	Date now;
	/*Make sender send packets to localhost and assert that all the
	  fields come out right.  This is also a test/demo of how the
	  external interface to sender and receiver should work.*/
	int i;

	try {
	    listOAddress = InetAddress.getAllByName(InetAddress.getLocalHost().getHostName());
	    for (i = 0; i< listOAddress.length; i++)
		System.out.println("localhost is: "+listOAddress[i]);


	    
	    outgoing = new IPTimeMonitorPacket();
	    now = new Date();
	    outgoing.setDateTime(now);
	    outgoing.setHostIP(InetAddress.getLocalHost());
	    outgoing.setComponentCode((short)69);
	    outgoing.setPacketVersion((short)42);
	    sender.sendPacket(outgoing);

	    
	    incoming = receiver.blockingGetPacket();
	    Assert.assertTrue(incoming != null);
	    Assert.assertTrue(incoming instanceof IPTimeMonitorPacket);

	    IPTimeMonitorPacket iptmp = (IPTimeMonitorPacket)incoming;

	    Assert.assertTrue(iptmp.getComponentCode() == 69);
	    Assert.assertTrue(iptmp.getPacketVersion() == 42);
	    Assert.assertTrue(iptmp.getHostIP().equals(InetAddress.getLocalHost()));
	    Assert.assertTrue(iptmp.getDateTime().equals(now));

	    /*Weirdness:
	      getLocalHost returns 192.168.0.1.
	      (NOT my address on the home network -- that's the router!)
	      getByName("localhost") gives 0:0:0:0:0:0:0:1 (loopback)
	      Sending to (getLocalHost()) -> the packet never reaches
	      me!
	      Sending to getByName("localhost") works.
	      But we don't want to put loopback (127.0.0.1) into packet!
	      If anything, from behind NAT what we'd want to put in is
	      the server's exeternal IP...
	    */
	
	} catch (UnknownHostException uhe) {
	    Assert.fail("I'm confused about localhost's address.");
	}
    }

    public void testGFTPPackets() {

	GFTPMonitorPacket outgoing;
	UsageMonitorPacket incoming;
	Date startDate, endDate;
	/*Make sender send GFTP packets to localhost and assert that all the
	  fields come out right.  This is also a test/demo of how the
	  external interface to sender and receiver should work.*/
	int i;


	    
	    startDate = new Date(1999, 12, 31);
	    endDate = new Date(2000, 1, 1);

	    sender.sendPacket(GFTPMonitorPacket.STOR_CODE,
			      startDate, endDate, (long)65535,
			      (long)7, (long)3, (long)32000, (long)64000,
			      (long)227, "Version1");
	    
	    incoming = receiver.blockingGetPacket();

	    Assert.assertTrue(incoming != null);
	    System.out.println("in testGFTP: incoming packet has component code "+ incoming.getComponentCode());
	    System.out.println("in testGFTP: is incoming packet instance of GFTPMonitorPacket?" + (incoming instanceof GFTPMonitorPacket));

	    Assert.assertTrue(incoming instanceof GFTPMonitorPacket);
	    GFTPMonitorPacket gmp = (GFTPMonitorPacket)incoming;


	    System.out.println("Here is gmp:");
	    gmp.display();

	    Assert.assertTrue(gmp.getComponentCode() == GFTPMonitorPacket.COMPONENT_CODE);
	    Assert.assertTrue(gmp.getPacketVersion() == GFTPMonitorPacket.VERSION_CODE);

	    Assert.assertTrue(gmp.isStorOperation());
	    Assert.assertFalse(gmp.isRetrOperation());

	    Assert.assertTrue(gmp.getStartTime().equals(startDate));
	    Assert.assertTrue(gmp.getEndTime().equals(endDate));
	    Assert.assertTrue(gmp.getNumBytes() == 65535);
	    Assert.assertTrue(gmp.getNumStripes() == 7);
	    Assert.assertTrue(gmp.getNumStreams() == 3);
	    Assert.assertTrue(gmp.getBufferSize() == 32000);
	    Assert.assertTrue(gmp.getBlockSize() == 64000);
	    Assert.assertTrue(gmp.getFTPReturnCode() == 227);
	    Assert.assertTrue(gmp.getGridFTPVersion().equals("Version1"));
    }

}
