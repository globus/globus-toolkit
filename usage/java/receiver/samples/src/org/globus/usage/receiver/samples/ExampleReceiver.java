package org.globus.usage.receiver.samples;

import java.io.InputStream;
import java.io.IOException;
import java.util.Properties;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.net.DatagramPacket;
import java.net.SocketAddress;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.receiver.Receiver;
import org.globus.usage.receiver.handlers.GridFTPPacketHandler;
import org.globus.usage.receiver.handlers.RFTPacketHandler;

/*An example of how the Receiver class can be used in a program:*/
public class ExampleReceiver {

    static Log log = LogFactory.getLog(ExampleReceiver.class);

    public static void main(String[] args) {
        int port = 0;
        String databaseDriverClass, databaseURL, defaultTable, gftpTable;
	String rftTable;
	int ringBufferSize = 0;
        Properties props;
        InputStream propsIn;
        Receiver receiver;
        GridFTPPacketHandler gftpHandler;
	RFTPacketHandler rftHandler;

        /*Open properties file (which gets compiled into jar) to read
          default port and database connection information:*/
        try {
            props = new Properties();
            propsIn = Receiver.class.getResourceAsStream("/receiver.properties");
            if (propsIn != null) {
                props.load(propsIn);
            }
	    else {
		log.error("Can't open properties file receiver.properties.");
	    }

            databaseDriverClass = props.getProperty("database-driver");
            databaseURL = props.getProperty("database-url");
            defaultTable = props.getProperty("default-table");
            gftpTable = props.getProperty("gftp-table");
	    rftTable = props.getProperty("rft-table");
            ringBufferSize = Integer.parseInt(props.getProperty("ringbuffer-size"));

            if (args.length == 1)
                /*Get listening port number from command line*/
                port = Integer.parseInt(args[0]);
            else {
                /*or else, read port from properties file:*/
                port = Integer.parseInt(props.getProperty("listening-port"));
            }

            if (port == 0) {
                throw new Exception("You must specify listening port either on the command line or in the properties file.");
            }
            
            /*When creating the receiver, pass it the port to listen on,
              the database connection class to use, the url to connect to your
              database, and the database table where default packets will be
	      written if no other handler takes them:*/
	    System.out.println("Starting receiver on port "+port+"; will write to database at "+databaseURL+"; Ringbuffer size is "+ringBufferSize);
            receiver = new Receiver(port, databaseDriverClass,
				    databaseURL, defaultTable,
				    ringBufferSize);
            
            /*gftpHandler is an example of a PacketHandler subclass.  I create
              one here, giving it the neccessary database information, and then
              register it to the receiver; it knows what to do with all
	      incoming GFTP usage packets.*/
            gftpHandler = new GridFTPPacketHandler(databaseURL,
                                                   gftpTable);
            receiver.registerHandler(gftpHandler);
	    
	    /*Let's handle RFT usage packets too.  All packets that aren't
	      GFTP or RFT will end up in the unknown_packets table.*/
	    rftHandler = new RFTPacketHandler(databaseURL, rftTable);
	    receiver.registerHandler(rftHandler);

	    //Other handlers can be registered here.

	    //start the control socket thread:
	    new ControlSocketThread(receiver, 4811).start();
        }
        catch (IOException e) {
            log.fatal("An IOException occurred when trying to create Receiver:" +e.getMessage());
        }
        catch (Exception e) {
            log.fatal("An exception occurred: " + e.getMessage(), e);
        }

        /*That's all... this thread ends, but the receiver has started listener
          and handler threads which will write incoming packets to the database.*/
    }
}


/*Thread used for interprocess communication, so that the receiver can be
  started/stopped/monitored remotely.*/
class ControlSocketThread extends Thread {

    private boolean shutDown;
    private Receiver receiver;
    private int controlPort;
    private DatagramSocket inSock, outSock;

    public ControlSocketThread (Receiver receiver, int controlPort) throws SocketException {
	this.receiver = receiver;
	this.controlPort = controlPort;
	this.shutDown = false;
	inSock = new DatagramSocket(controlPort);
	outSock = new DatagramSocket();
    }

    public void run() {
	/*When we get a packet on the control socket, either respond with
	  the receiver.getStatus(), or shut down the receiver.*/
	DatagramPacket inPacket, outPacket;
	byte[] outBuffer;
	byte[] inBuffer = new byte[100];
	SocketAddress remoteAddr;

	while (!shutDown) {
	    //receive packet on controlPort.
	    try {
		inPacket = new DatagramPacket(inBuffer, inBuffer.length);
		inSock.receive(inPacket);

		if (true == false/*packet is shutdown packet*/) {
		    receiver.shutDown();
		    shutDown = true;
		}
		else {
		    //send back packet with receiver.getStatus();
		    remoteAddr = inPacket.getSocketAddress();
		    outBuffer = receiver.getStatus().getBytes();
		    outPacket = new DatagramPacket(outBuffer, outBuffer.length, remoteAddr);
		    outSock.send(outPacket);
		}
	    }
	    catch (Exception e) {}
	}

	try {
	    inSock.close();
	    outSock.close();
	} catch (Exception e) {}
    }

}
