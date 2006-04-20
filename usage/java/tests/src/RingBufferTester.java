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

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.receiver.RingBuffer;
import org.globus.usage.receiver.RingBufferArray;

public class RingBufferTester extends TestCase {

    private RingBuffer ringBuffer;
    private 	CustomByteBuffer pack1, pack2, pack3, pack4, pack5, pack6;

    public RingBufferTester(String name) {
	super(name);
    }

    protected void setUp() {
	ringBuffer = new RingBufferArray(5);

	pack1 = new CustomByteBuffer(1);
	pack2 = new CustomByteBuffer(1);
	pack3 = new CustomByteBuffer(1);
	pack4 = new CustomByteBuffer(1);
	pack5 = new CustomByteBuffer(1);
	pack6 = new CustomByteBuffer(1);

    }

    protected void tearDown() {

    }

    public void testRingBuffer() {

    /*Make a queue of 10 objects; assert that getCapacity returns 10 and
      getNumObjects returns 0, isEmpty returns true.
      try to do getNext and assert that it returns null.
      Insert an object; assert that isEmpty and isFull are false, getNumObjects
      is 1.  do getNext, assert that the object we get back out is the same
      as the one we put in.  Assert that after getting next isEmpty is true
      again.
      Put in 10 objects.  Assert that isFull is now true.  Try to insert an
      11th and assert that insert returns false.  do getNext ten times and
      assert that we get all the objects back out in the same order we
      put them in.*/

	Assert.assertTrue(ringBuffer.isEmpty());
	Assert.assertFalse(ringBuffer.isFull());
	Assert.assertTrue(ringBuffer.getNumObjects() == 0);
	Assert.assertTrue(ringBuffer.getCapacity() == 5);
	//	Assert.assertTrue(ringBuffer.getNext() == null);
	//that will hang without another thread to wake it up

	Assert.assertTrue(ringBuffer.insert(pack1));
	Assert.assertFalse(ringBuffer.isEmpty());
	Assert.assertFalse(ringBuffer.isFull());
	Assert.assertTrue(ringBuffer.getNumObjects() == 1);
	Assert.assertTrue(ringBuffer.getNext() == pack1);
	Assert.assertTrue(ringBuffer.isEmpty());
	
	Assert.assertTrue(ringBuffer.insert(pack1));
	Assert.assertTrue(ringBuffer.insert(pack2));
	Assert.assertTrue(ringBuffer.insert(pack3));
	Assert.assertTrue(ringBuffer.insert(pack4));
	Assert.assertTrue(ringBuffer.insert(pack5));
	Assert.assertTrue(ringBuffer.getNumObjects() == 5);
	Assert.assertTrue(ringBuffer.isFull());
	Assert.assertFalse(ringBuffer.isEmpty());
	Assert.assertFalse(ringBuffer.insert(pack6));
	Assert.assertTrue(ringBuffer.getNext() == pack1);
	Assert.assertTrue(ringBuffer.getNumObjects() == 4);
	Assert.assertTrue(ringBuffer.getNext() == pack2);
	Assert.assertTrue(ringBuffer.getNumObjects() == 3);
	Assert.assertTrue(ringBuffer.getNext() == pack3);
	Assert.assertTrue(ringBuffer.getNumObjects() == 2);
	Assert.assertTrue(ringBuffer.getNext() == pack4);
	Assert.assertTrue(ringBuffer.getNumObjects() == 1);
	Assert.assertTrue(ringBuffer.getNext() == pack5);
	Assert.assertTrue(ringBuffer.getNumObjects() == 0);

    }
}
