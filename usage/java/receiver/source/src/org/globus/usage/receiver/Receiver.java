package org.globus.usage.receiver;

import java.util.LinkedList;
import java.util.ListIterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class Receiver {
    private static Log log = LogFactory.getInstance(Receiver.class);

    RingBuffer theRing; /*receiver thread puts packets in here; handler
                          thread reads them out and pass them through the 
                          handlers.*/

    LinkedList handlerList; /*Every handler in this list gets a crack at
                              the incoming packets.*/

    ReceiverThread theRecvThread;
    HandlerThread theHandleThread;
    private final static int RING_BUFFER_SIZE = 100;


    /*Creates a receiver which will listen on the given port and write
      packets to the given database.*/
    public Receiver(int port, String driver, String db,
                    String table, int ringBufferSize) throws IOException {

        theRing = new RingBuffer(ringBufferSize);
        handlerList = new LinkedList();

        /*Start two threads: a listener thread which listens on the port, and
          a handler thread to take packets out of the ring buffer and
          pass them through all registered handlers...*/
        theRecvThread = new ReceiverThread(port, theRing);
        theRecvThread.start();
        theHandleThread = new HandlerThread(handlerList, driver, db, table, theRing);
        theHandleThread.start();
    }

    /*Constructor with no specified ringBuffer size uses default*/
    public Receiver(int port, String driver, String db, String table)
        throws IOException {

        this(port, driver, db, table, RING_BUFFER_SIZE);
    }


    public void registerHandler(PacketHandler myHandler) {

        /*once the handler is registered, it will be called every time a
          packet comes in bearing a matching component code and packet version
          code.  If multiple handlers are installed that handle the same code,
          ALL will be triggered!  Starting with the most recently registered.
        */

        synchronized (handlerList) {
            handlerList.addFirst(myHandler);
        }
        
    }

    /*I don't recommend using this method, which blocks until a packet
      comes in, then returns the packet.  I wrote it just to test the
      receiver*/
    public UsageMonitorPacket blockingGetPacket() {
        CustomByteBuffer bufFromRing;
        UsageMonitorPacket packet;
        short code;

        while (theRing.isEmpty()) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ie) {
            }
        }
        
        bufFromRing = theRing.getNext();
        code = bufFromRing.getShort();
        switch (code) {
            case 0:
                packet = new GFTPMonitorPacket();
                break;
            case 69:
                packet = new IPTimeMonitorPacket();
                break;
            default:
                packet = new UsageMonitorPacket();
        }

        bufFromRing.rewind();
        packet.parseByteArray(bufFromRing.array());

        return packet;
    }

    public void shutDown() {
        log.debug("shutting down receiver.");
        theRecvThread.shutDown();
        theHandleThread.shutDown();
    }

}

/*Should this actually be an inner class of Receiver?*/
class ReceiverThread extends Thread {

    private static Category log = Category.getInstance(ReceiverThread.class.getName());

    protected DatagramSocket socket = null;
    protected int listeningPort;
    private RingBuffer theRing; /*a reference to the one in Receiver*/
    private boolean stillGood = true;

    public ReceiverThread(int port, RingBuffer ring) throws IOException {
        super("UDPReceiverThread");

        this.listeningPort = port;
        this.theRing = ring;
        socket = new DatagramSocket(listeningPort);
        log.info("Receiver is listening on port " + port);
    }

    public void run() {
        byte[] buf;
        DatagramPacket packet;
        CustomByteBuffer storage;

        while(stillGood) {
            buf = new byte[UsageMonitorPacket.packetSize];
            packet = new DatagramPacket(buf, buf.length);

            try {
                socket.receive(packet);

                storage = CustomByteBuffer.wrap(buf);
                log.info("Packet received!");
                
                /*Put packet into ring buffer:*/
                if (!theRing.insert(storage)) {
                    //failed == ring is full
                    log.warn("WARNING:  Ring buffer is FULL.  We are LOSING PACKETS.");
                    //todo:  throw an exception?
                }

            } catch (IOException e) {
                log.error("When trying to recieve, an IO exception occurred:");
            }
            /*Todo: if the socket is no longer open here, for some reason,
              should we maybe try to open a new socket?*/
        }

    }

    public void shutDown() {
        stillGood = false; //lets the loop in run() finish.
        socket.close();
    }
}

class HandlerThread extends Thread {

    private LinkedList handlerList; /*a reference to the one in Receiver*/
    private RingBuffer theRing; /*a reference to the one in Receiver*/
    private boolean stillGood = true;
    private DefaultPacketHandler theDefaultHandler;

    public HandlerThread(LinkedList list, String driver, String db, String table, RingBuffer ring) {
        super("UDPHandlerThread");

        this.handlerList = list;
        this.theRing = ring;
        theDefaultHandler = new DefaultPacketHandler(driver, db, table);
    }

    /*This thread waits on the RingBuffer; when packets come in, it starts
      reading them out and letting the handlers have them.*/
    public void run() {
        short componentCode, versionCode;
        CustomByteBuffer bufFromRing;

        while(stillGood) {
            /*todo: Maybe the thread should wait() while the ring is empty,
              and the receiverThread should notify() this thread when
              stuff comes in...*/
            while (theRing.isEmpty()) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ie) {
                }
            }
        
            bufFromRing = theRing.getNext();
            componentCode = bufFromRing.getShort();
            versionCode = bufFromRing.getShort();
            bufFromRing.rewind();
            tryHandlers(bufFromRing, componentCode, versionCode);
        }
    }


    private void tryHandlers(CustomByteBuffer bufFromRing, short componentCode,
                             short versionCode) {
        UsageMonitorPacket packet;
        boolean hasBeenHandled;
        PacketHandler handler;
        ListIterator it;
        
        /*This next bit is synchronized to make sure a handler can't
              be registered while we're walking the list...*/
        synchronized(handlerList) {
            hasBeenHandled = false;                
            for (it = handlerList.listIterator(); it.hasNext(); ) {
                handler = (PacketHandler)it.next();
                if (handler.doCodesMatch(componentCode, versionCode)) {
                    packet = handler.instantiatePacket(bufFromRing);
                    packet.parseByteArray(bufFromRing.array());
                    handler.handlePacket(packet);
                    bufFromRing.rewind();
                    hasBeenHandled = true;
                }
            }
            if (!hasBeenHandled) {
                packet = theDefaultHandler.instantiatePacket(bufFromRing);
                packet.parseByteArray(bufFromRing.array());
                theDefaultHandler.handlePacket(packet);
            }
        }
        /*If multiple handlers return true for doCodesMatch, each
          handler will be triggered, each with its own separate copy of
          the packet.  theDefaultHandler will be called only if no other
          handlers trigger.*/        
    }


    public void shutDown() {
        stillGood = false; //lets the loop in run() finish
    }
}
