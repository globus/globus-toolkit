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

package org.globus.usage.receiver;

import org.globus.usage.packets.CustomByteBuffer;

/*I don't think this class exists yet in the java platform.
  It's pretty trivial to implement one.
Since one thread will be writing into this while another thread reads
out, it must be thread-safe.*/

public class RingBuffer {

    private CustomByteBuffer[] queue;
    private int numObjects, maxObjects;
    private int inputIndex, outputIndex;

    public RingBuffer(int capacity) {
        maxObjects = capacity;
        numObjects = 0;
        queue = new CustomByteBuffer[maxObjects];
        inputIndex = outputIndex = 0;
    }

    /*Returns and removes next object (FIFO) if there is one;
      if ringbuffer is empty, returns null.*/
    public synchronized CustomByteBuffer getNext() {
        try {
            while (numObjects == 0) {
                wait();
            }
        } catch (InterruptedException e) {
            return null;
        }
        
        CustomByteBuffer theNext;
        theNext = queue[outputIndex];
        queue[outputIndex] = null;
        outputIndex = (outputIndex + 1) % maxObjects;
        numObjects --;
        return theNext;
    }

    /*Returns true if insert was successful, false if ringbuffer 
      was already full and the insert failed.*/
    public synchronized boolean insert(CustomByteBuffer newBuf) {
        if (numObjects == maxObjects) {
            return false;
        } else {
            queue[inputIndex] = newBuf;
            inputIndex = (inputIndex + 1) % maxObjects;
            numObjects ++;
            notify();
            return true;
        }
    }

    /*These query methods are synchronized so that they can't be called when
      the other thread is halfway through inserting or removing, which might
      give the wrong answer.*/
    public synchronized boolean isFull() {
        return numObjects == maxObjects;
    }

    public synchronized boolean isEmpty() {
        return numObjects == 0;
    }

    public synchronized int getCapacity() {
        return maxObjects;
    }
    
    public synchronized int getNumObjects() {
        return numObjects;
    }

    /*JUnit tests*/

}
