package org.globus.usage.packets;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ReadOnlyBufferException;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/*The basic packet format is:
  16 bit component code
  16 bit packet version code
  and then a chunk of binary data, up to max 1472 bytes.
  Interpretation of data depends on the codes in the first 32 bits.
  Subclass UsageMonitorPacket to define your own format.*/
public class UsageMonitorPacket {

    public static final int packetSize = 1472; //bytes
    static Log log = LogFactory.getLog(UsageMonitorPacket.class);

    protected short componentCode;
    protected short packetVersion;
    protected byte[] binaryContents;

    public UsageMonitorPacket() {
    }

    public void setComponentCode(short c) {
        componentCode = c;
    }

    public int getComponentCode() {
        return componentCode;
    }

    public void setComponentVersion(short v) {
        packetVersion = v;
    }

    public int getComponentVersion() {
        return packetVersion;
    }

    public byte[] getBinaryContents () {
        return binaryContents;
    }

    /*When defining your own packet type, override packCustomFields to
      write all your custom data into the ByteBuffer; and override
      unpackCustomFields to read the data back out of the ByteBuffer in
      the same order.*/
    public  void packCustomFields(CustomByteBuffer buf) {

    }

    public void unpackCustomFields(CustomByteBuffer buf) {

    }

    /*To get the byte array suitable for stuffing into a packet:*/
    private byte[] toByteArray() {
        CustomByteBuffer buf = new CustomByteBuffer(packetSize);

        buf.putShort(componentCode);
        buf.putShort(packetVersion);

        packCustomFields(buf);
        
        return buf.array();
    }

    public void parseByteArray(byte[] input) {
        CustomByteBuffer buf = CustomByteBuffer.wrap(input);

        componentCode = buf.getShort();
        packetVersion = buf.getShort();

        unpackCustomFields(buf);

        binaryContents = input; //save this... it'll go into database.
    }

    public void sendPacket(DatagramSocket socket, 
                    InetAddress destination, 
                    int destPort) throws IOException {
        byte[] sendBuf = toByteArray();
        DatagramPacket packet = new DatagramPacket(sendBuf, sendBuf.length,
                                                   destination, destPort);
        socket.send(packet);
    }

    /*destinations and destPorts must contain the same number of elements.
      It's possible that some of the destinations are valid while others are
      null because they could not be resolved, so check each one.*/
    public void sendPacketToMultiple(DatagramSocket socket, 
                              InetAddress[] destinations,
                              int[] destPorts) throws IOException {
        int i;
        byte[] sendBuf = toByteArray();
        
        if (destinations.length != destPorts.length) {
            log.error("In sendPacketToMultiple: number of destinations and destination ports do not match.");
            return;
        }

        for (i=0; i<destinations.length; i++)
            if (destinations[i] != null)
                socket.send(new DatagramPacket(sendBuf,
                                               sendBuf.length,
                                               destinations[i],
                                               destPorts[i]));

    }

    /*If you want to send to the same port on each of the multiple
      hosts (the most likely case):*/
    public void sendPacketToMultiple(DatagramSocket socket,
                              InetAddress[] destinations,
                              int destPort) throws IOException {

        int i;
        byte[] sendBuf = toByteArray();

        for (i=0; i<destinations.length; i++)
            if (destinations[i] != null)
                socket.send(new DatagramPacket(sendBuf,
                                               sendBuf.length,
                                               destinations[i],
                                               destPort));
    }

    /*The following version of sendPacket doesn't take a socket -- it
      creates one and destroys it at the end.  This is not very efficient
      if you're going to be sending a lot of packets, but it may be
      convenient.*/
    public void sendPacket(InetAddress destination, int destPort) throws IOException{
        DatagramSocket socket = new DatagramSocket();
        sendPacket(socket, destination, destPort);
        socket.close();
    }

    public void sendPacketToMultiple(InetAddress[] destinations,
                              int destPort) throws IOException {
        DatagramSocket socket = new DatagramSocket();
        sendPacketToMultiple(socket, destinations, destPort);
        socket.close();
    }



    /*This puts contents to log -- just for debugging purposes*/
    public void display() {
        log.info("This packet contains:");
        log.info("Component code = " + componentCode);
        log.info("Component packet version = " + packetVersion);
    }
}
