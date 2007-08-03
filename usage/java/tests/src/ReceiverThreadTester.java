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
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.SocketException;
import java.io.IOException;
import java.util.Properties;

import org.globus.usage.receiver.ReceiverThread;
import org.globus.usage.receiver.RingBuffer;
import org.globus.usage.receiver.RingBufferArray;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;

public class ReceiverThreadTester extends TestCase {
    private final static int testPort = 12180;
    private ReceiverThread receiverThread;
    private RingBuffer theRing;

    public ReceiverThreadTester(String name) {
	super(name);
    }

    protected void setUp() {
	theRing = new RingBufferArray(100);
	try {   
            Properties props = new Properties();

            props.setProperty("listening-port", Integer.toString(testPort));
	    receiverThread = new ReceiverThread(theRing, props);
	    receiverThread.start();
	}
	catch (Exception e) {
	    System.err.println("creating receiverThread:" + e.getMessage());
	}
    }

    protected void tearDown() {
	receiverThread.shutDown();
    }

    private void sendPacketToSelf(byte[] outData) throws IOException, UnknownHostException, SocketException {
	DatagramSocket outSock;
	DatagramPacket outPack;

	outSock = new DatagramSocket();
	outPack = new DatagramPacket(outData, outData.length);
	outPack.setPort(testPort);
	outPack.setAddress(InetAddress.getLocalHost());
	outSock.send(outPack);
	outSock.close();
    }

    public void testTrimmingPacket() {
	byte[] outData;
	CustomByteBuffer inBuf;

	try {
	    //Send a packet of three bytes to the receiver:
	    outData = new byte[] {36, 24, 36};
	    sendPacketToSelf(outData);

	    inBuf = theRing.getNext();

	    //Send a 3-byte packet and make sure that resulting buffer
	    //is no more than 3 bytes.
	    Assert.assertTrue("inbuf must not be null", inBuf != null);
	    Assert.assertEquals("inbuf must have 3 bytes",
				inBuf.remaining(), 3);
	    Assert.assertEquals("first byte", inBuf.get(), (byte)36);
	    Assert.assertEquals("2nd byte", inBuf.get(), (byte)24);
	    Assert.assertEquals("3rd byte", inBuf.get(), (byte)36);
	    Assert.assertEquals("inbuf should be at end",
				inBuf.remaining(), 0);
	} catch (Exception e) {
	    Assert.fail("Socket experiment failed: "+e.getMessage());
	}
    }

    public void testNullsInPacket() {
	    //Now send a large packet with null bytes in the middle and
	    //make sure that it does not get truncated at the null bytes.
	    
	byte[] outData;
	CustomByteBuffer inBuf;
	CustomByteBuffer outBuf;

	try {
	    outBuf = new CustomByteBuffer(32);
	    outBuf.put(new String("Hello").getBytes());
	    outBuf.put((byte)0);
	    outBuf.put(new String("World!").getBytes());

	    outData = outBuf.array();

	    sendPacketToSelf(outData);
	    inBuf = theRing.getNext();

	    //	    System.out.println(new String(inBuf.array()));
	    Assert.assertEquals(inBuf.array().length, 12);

	} catch (Exception e) {
	    Assert.fail("Socket experiment failed: "+e.getMessage());
	}
    }

    public void testShortAndLongPackets() {
	//Send a short packet, then a long packet, make sure the longer one
	//is not truncated to the length of the shorter one...
	CustomByteBuffer inBuf;
	try {
	    sendPacketToSelf(new byte[] {1, 2, 3, 4, 0});

	    sendPacketToSelf(new byte[] {1, 2, 3, 4, 5, 6 , 7, 8, 9, 10});

	    inBuf = theRing.getNext();
	    Assert.assertEquals(inBuf.array().length, 5);
	    Assert.assertEquals(inBuf.get(), (byte)1);
	    Assert.assertEquals(inBuf.get(), (byte)2);
	    Assert.assertEquals(inBuf.get(), (byte)3);
	    Assert.assertEquals(inBuf.get(), (byte)4);
	    Assert.assertEquals(inBuf.get(), (byte)0);

	    inBuf = theRing.getNext();
	    
	    Assert.assertEquals(inBuf.array().length, 10);
	    Assert.assertEquals(inBuf.get(), (byte)1);
	    Assert.assertEquals(inBuf.get(), (byte)2);
	    Assert.assertEquals(inBuf.get(), (byte)3);
	    Assert.assertEquals(inBuf.get(), (byte)4);
	    Assert.assertEquals(inBuf.get(), (byte)5);
	    Assert.assertEquals(inBuf.get(), (byte)6);
	    Assert.assertEquals(inBuf.get(), (byte)7);
	    Assert.assertEquals(inBuf.get(), (byte)8);
	    Assert.assertEquals(inBuf.get(), (byte)9);
	    Assert.assertEquals(inBuf.get(), (byte)10);
	} catch (Exception e) {
	    Assert.fail("Socket experiment failed: "+e.getMessage());
	}
    }

    public void testNullComponentCode() {
	//We have a bug that says "failed to add null value in not null
	//attribute component_code".  So how can component_code be null?
	CustomByteBuffer inBuf;
	CustomByteBuffer outBuf;
	UsageMonitorPacket pack;

	try {
	    outBuf = new CustomByteBuffer(32);
	    outBuf.putShort((short)6);
	    outBuf.putShort((short)7);
	    sendPacketToSelf(outBuf.array());

	    
	    inBuf = theRing.getNext();
	    pack = new UsageMonitorPacket();
	    pack.parseByteArray(inBuf.array());	    
	    Assert.assertEquals(pack.getComponentCode(), (short)6);
	    Assert.assertEquals(pack.getPacketVersion(), (short)7);
	} catch (Exception e) {
	    Assert.fail("Socket experiment failed: "+e.getMessage());
	}

	//Hypothesis: datagramPacket.getLength returns something too short,
	//custom byte buffer gets prematurely truncated, buf.get fails
	//because array is out of bounds.  How to test this?
    }
}
