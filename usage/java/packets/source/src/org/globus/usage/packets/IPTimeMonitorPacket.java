package org.globus.usage.packets;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ReadOnlyBufferException;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/*To the component code and packet version number fields in the
  base class, this subclass adds source IP and time-sent fields.
  It uses a 1-byte flag to indicate whether it holds an IPv4 address
  (32 bits) or an IPv6 address (128 bits).
  If you want to include these in your packets, make your packet
  format a subclass of IPTimeMonitorPacket.*/
public class IPTimeMonitorPacket extends UsageMonitorPacket {
    static Log log = LogFactory.getLog(IPTimeMonitorPacket.class);

    protected long timeSent;
    protected InetAddress senderAddress;

    public void setDateTime(Date d) {
        timeSent = d.getTime();
    }

    public Date getDateTime() {
        return new Date(timeSent);
    }

    public void setHostIP(InetAddress a) {
        senderAddress = a;
    }

    public InetAddress getHostIP() {
        return senderAddress;
    }

    public void packCustomFields(CustomByteBuffer buf) {
        byte[] addressByteArray;
        int i;

            buf.putLong(timeSent);

        log.debug("Turning PacketWrapper into byte array.");
        if (senderAddress instanceof Inet4Address) {
            log.debug("This outgoing packet is IPv4.");
            buf.put((byte)4);
        }
        else if (senderAddress instanceof Inet6Address) {
            log.debug("This outgoing packet is IPv6.");
            buf.put((byte)6);
        }
        addressByteArray = senderAddress.getAddress();
        
        log.debug("addressByteArray size: " + addressByteArray.length);

        for (i = 0; i < addressByteArray.length; i++) {
            log.debug("byte "+i+": "+addressByteArray[i]);
        }
        buf.put(addressByteArray);
    }

    public void unpackCustomFields(CustomByteBuffer buf) {
        byte[] addressByteArray = null;
        byte IPversionFlag;
        int i;

        timeSent = buf.getLong();
        
        IPversionFlag = buf.get();
        if (IPversionFlag == 4) {
            addressByteArray = new byte[4];
            buf.get(addressByteArray);
            log.debug("Found an IPv4 src address in this packet.");
            for (i = 0; i<4; i++)
                log.debug("Byte "+i+": "+addressByteArray[i]);
        } 
        else if (IPversionFlag == 6) {
            addressByteArray = new byte[16];
            buf.get(addressByteArray);
           log.debug("Found an IPv6 src address in this packet.");
            for (i = 0; i<16; i++)
                log.debug("Byte "+i+": "+addressByteArray[i]);

         }
        else
            log.error("IP version code neither 4 nor 6; can't proceed.");

        try {
            senderAddress = InetAddress.getByAddress(addressByteArray);
        } catch (UnknownHostException uhe) {
            log.error("This packet came from a host I can't identify.");
        }

    }

    public void display() {
        super.display();
        log.info("Packet was sent at " + getDateTime());
        log.info("From the address " + senderAddress);
    }
}

