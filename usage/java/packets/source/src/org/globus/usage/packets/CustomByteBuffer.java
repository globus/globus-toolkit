/*
 * This file or a portion of this file is licensed under the terms of the
 * Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without modifications,
 * you must include this notice in the file.
 */
package org.globus.usage.packets;

/*
 * This replaces the java.nio.ByteBuffer class which is not in Java 
 * platform 1.3.
 */
public class CustomByteBuffer {

    private int maxSize;
    private int bytesUsed;
    private int pointer;
    private byte[] internalArray;

    private final static int LONG_SIZE = 8;
    private final static int INT_SIZE = 4;
    private final static int SHORT_SIZE = 2;

    public CustomByteBuffer(int maxSize) {
        this.internalArray = new byte[maxSize];
        this.maxSize = maxSize;
        this.pointer = bytesUsed = 0;
    }

    private CustomByteBuffer() {
    }

    public static CustomByteBuffer wrap(byte[] existingArray) {
        
        CustomByteBuffer newByteBuffer = new CustomByteBuffer();
        newByteBuffer.internalArray = existingArray;
        newByteBuffer.maxSize = newByteBuffer.bytesUsed = existingArray.length;
        newByteBuffer.shrink();
        newByteBuffer.pointer = 0;

        return newByteBuffer;
    }

    public void shrink() {
        /*Shrink to minimum occupied size... be careful with this*/
        byte[] smallerArray = new byte[bytesUsed];
        System.arraycopy(this.internalArray, 0, smallerArray, 0, bytesUsed);
        this.internalArray = smallerArray;
        this.maxSize = internalArray.length;
    }

    public byte[] array() {
        shrink();
        return this.internalArray;
    }

    public void rewind() {
        this.pointer = 0;
    }
    
    public byte get() {
        byte nextByte = this.internalArray[this.pointer];
        this.pointer++;
        return nextByte;
    }
    
    public void get(byte[] dataGoesHere) {
        get(dataGoesHere, dataGoesHere.length);
    }
    
    public void get(byte[] dataGoesHere, int numBytes) {
        System.arraycopy(this.internalArray, this.pointer, 
                         dataGoesHere, 0, 
                         numBytes);
        this.pointer += numBytes;
    }

    public long getLong() {
        long out = 0;
        for (int i=LONG_SIZE-1; i>=0; i--) {
            out = out << 8;
            out |= (this.internalArray[this.pointer+i] & 0xFF);
        }
        this.pointer += LONG_SIZE;
        return out;
    }

    public int getInt() {
        int out = 0;
        for (int i=INT_SIZE-1; i>=0; i--) {
            out = out << 8;
            out |= (this.internalArray[this.pointer+i] & 0xFF);
        }
        this.pointer += INT_SIZE;
        return out;
    }

    public short getShort() {
        short out = 0;
        for (int i=SHORT_SIZE-1; i>=0; i--) {
            out = (short)(out << 8);
            out |= (this.internalArray[this.pointer+i] & 0xFF);
        }
        this.pointer += SHORT_SIZE;
        return out;
    }

    public void put(byte datum) {
        this.internalArray[this.pointer] = datum;
        this.pointer++;
        if (this.pointer > this.bytesUsed) {
            this.bytesUsed = this.pointer;
        }
    }

    public void put(byte[] data) {
        put(data, data.length);
    }

    public void put(byte[] data, int numBytes) {
        System.arraycopy(data, 0, 
                         this.internalArray, this.pointer, 
                         numBytes);
        this.pointer += numBytes;
        if (this.pointer > this.bytesUsed) {
            this.bytesUsed = this.pointer;
        }
    }
    
    public void putLong(long datum) {
        for (int i=0; i<LONG_SIZE; i++) {
            this.internalArray[this.pointer + i] = (byte)datum;
            datum = datum >> 8;
        }
        this.pointer += LONG_SIZE;
        if (this.pointer > this.bytesUsed) {
            this.bytesUsed = pointer;
        }
    }

    public void putInt(int datum) {
        for (int i=0; i<INT_SIZE; i++) {
            this.internalArray[this.pointer + i] = (byte)datum;
            datum = datum >> 8;
        }
        this.pointer += INT_SIZE;
        if (this.pointer > this.bytesUsed) {
            this.bytesUsed = pointer;
        }
    }

    public void putShort(short datum) {
        for (int i=0; i<SHORT_SIZE; i++) {
            this.internalArray[this.pointer + i] = (byte)datum;
            datum = (short)(datum >> 8);
        }
        this.pointer += SHORT_SIZE;
        if (this.pointer > this.bytesUsed) {
            this.bytesUsed = pointer;
        }
    }
}
