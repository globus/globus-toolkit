package org.globus.usage.packets;

/*This replaces the java.nio.ByteBuffer class which is not in Java platform 1.3.*/

public class CustomByteBuffer {

    private int maxSize, bytesUsed;
    private int pointer;
    private byte[] internalArray;

    private final static int LONG_SIZE = 8;
    private final static int INT_SIZE = 4;
    private final static int SHORT_SIZE = 2;
    

    public CustomByteBuffer(int maxSize) {
        internalArray = new byte[maxSize];
        this.maxSize = maxSize;
        pointer = bytesUsed = 0;
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

        System.arraycopy(internalArray, 0, smallerArray, 0, bytesUsed);
        internalArray = smallerArray;
        maxSize = internalArray.length;
    }

    public byte[] array() {
        shrink();
        return internalArray;
    }

    public void rewind() {
        pointer = 0;
    }

    public byte get() {
        byte nextByte = internalArray[pointer];
        pointer++;
        return nextByte;
    }
    
    public void get(byte[] dataGoesHere) {
        get(dataGoesHere, dataGoesHere.length);
    }

    public void get(byte[] dataGoesHere, int howManyBytes) {
        int i;
        for (i=0; i<howManyBytes; i++) {
            dataGoesHere[i] = internalArray[pointer];
            pointer++;
        }
    }

    public long getLong() {
        long out = 0;
        int i;

        for (i=LONG_SIZE-1; i>=0; i--) {
            out = out << 8;
            out |= (internalArray[pointer+i] & 0xFF);
        }
        pointer += LONG_SIZE;
        return out;
    }

    public int getInt() {
        int out = 0;
        int i;

        for (i=INT_SIZE-1; i>=0; i--) {
            out = out << 8;
            out |= (internalArray[pointer+i] & 0xFF);
        }
        pointer += INT_SIZE;
        return out;
    }

    public short getShort() {
        short out = 0;
        int i;

        for (i=SHORT_SIZE-1; i>=0; i--) {
            out = (short)(out << 8);
            out |= (internalArray[pointer+i] & 0xFF);
        }
        pointer += SHORT_SIZE;
        return out;
    }

    public void put(byte datum) {
        internalArray[pointer] = datum;
        pointer++;
        if (pointer > bytesUsed)
            bytesUsed = pointer;
    }

    public void put(byte[] data) {
        put(data, data.length);
    }

    public void put(byte[] data, int numBytes) {
        int i;
        for (i=0; i<numBytes; i++) {
            internalArray[pointer] = data[i];
            pointer++;
        }
        if (pointer > bytesUsed)
            bytesUsed = pointer;

    }

    public void putLong(long datum) {
        int i;
        
        for (i=0; i<LONG_SIZE; i++) {
            internalArray[pointer + i] = (byte)datum;
            datum = datum >> 8;
        }

        pointer += LONG_SIZE;
        if (pointer > bytesUsed)
            bytesUsed = pointer;
    }

    public void putInt(int datum) {
        int i;
        
        for (i=0; i<INT_SIZE; i++) {
            internalArray[pointer + i] = (byte)datum;
            datum = datum >> 8;
        }

        pointer += INT_SIZE;
        if (pointer > bytesUsed)
            bytesUsed = pointer;
    }

    public void putShort(short datum) {
        int i;
        
        for (i=0; i<SHORT_SIZE; i++) {
            internalArray[pointer + i] = (byte)datum;
            datum = (short)(datum >> 8);
        }

        pointer += SHORT_SIZE;
        if (pointer > bytesUsed)
            bytesUsed = pointer;
    }
}
