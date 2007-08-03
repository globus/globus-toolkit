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

import org.globus.usage.receiver.HandlerThread;
import org.globus.usage.receiver.RingBuffer;
import org.globus.usage.receiver.RingBufferArray;
import org.globus.usage.receiver.handlers.PacketHandler;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;

public class HandlerThreadTester extends TestCase {
    private final static int testPort = 12180;
    private HandlerThread handlerThread;
    private RingBuffer theRing;

    public HandlerThreadTester(String name) {
	super(name);
    }

    protected void setUp() {
	theRing = new RingBufferArray(100);
	try {   
            Properties props = new Properties();

            props.setProperty("handlers", "FakeHandler");
            props.setProperty("component-code", "1");
            props.setProperty("packet-version", "1");

	    handlerThread = new HandlerThread(theRing, props);
	    handlerThread.start();
	}
	catch (Exception e) {
	    System.err.println("creating handlerThread:" + e.getMessage());
	}
    }

    protected void tearDown() {
	handlerThread.shutDown();
    }

    public void testHandlerDispatch() {
        CustomByteBuffer buf = new CustomByteBuffer(1500);

        buf.putShort((short) 1);
        buf.putShort((short) 1);
        buf.rewind();

        theRing.insert(buf);
        synchronized(FakeHandler.class) {
            while (FakeHandler.skipped == 0 && FakeHandler.handled == 0) {
                try {
                    FakeHandler.class.wait();
                } catch (InterruptedException ie) {
                    ;
                }
            }
            Assert.assertEquals(FakeHandler.handled, 1);
            Assert.assertEquals(FakeHandler.skipped, 0);
        }

        buf = new CustomByteBuffer(1500);
        buf.putShort((short) 1);
        buf.putShort((short) 2);
        buf.rewind();

        handlerThread.resetCounts();

        theRing.insert(buf);
        synchronized(FakeHandler.class) {
            while (FakeHandler.skipped == 0 && FakeHandler.handled == 0) {
                try {
                    FakeHandler.class.wait();
                } catch (InterruptedException ie) {
                    ;
                }
            }
            Assert.assertEquals(FakeHandler.handled, 0);
            Assert.assertEquals(FakeHandler.skipped, 1);
        }

    }
}
