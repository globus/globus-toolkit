package org.globus.usage;

import junit.framework.TestCase;
import junit.framework.Test;
import junit.framework.Assert;
import junit.framework.TestSuite;
import java.util.Date;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.SocketException;
import java.io.IOException;

import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.DriverManager;

import org.globus.usage.packets.*;
import org.globus.usage.packets.samples.ExampleGFTPSender;
import org.globus.usage.receiver.*;
import org.globus.usage.receiver.samples.ExampleReceiver;
import org.globus.usage.receiver.handlers.*;

public class UnitTester extends TestCase {
    static final int portNum = 4811;
	
    static final String dbdriver = "org.postgresql.Driver";
    static final String dbURL = "database-url = jdbc:postgresql://mayed.mcs.anl.gov/guss?user=jdicarlo&password=abcdefg";
    static final int buffersize = 128;
    static final String table = "unknown_packets";


    public UnitTester(String name) {
	super(name);
    }

    public void testGFTPTextFormat() {
	//To really test this properly we need to get some captive
	//byte buffers to feed it...

	    //for now, try reading the id = 1 blob out of unknown-packets
	    //on mayed.
	    //select contents from unknown_packets where versioncode=0
	    //and componentcode = 0
	Connection con;
	PreparedStatement pstmt;
	ResultSet rs;
	CustomByteBuffer buf;
	GridFTPPacketHandler myHandler;
	UsageMonitorPacket maybePack;
	GFTPTextPacket pack;
	try {
	    Class.forName(dbdriver);
	    con = DriverManager.getConnection(dbURL);

	    pstmt = con.prepareStatement("SELECT contents FROM unknown_packets WHERE (componentcode = 0) AND (versioncode = 0);");
	    rs = pstmt.executeQuery();

	    Assert.assertTrue(rs.next());
	
	    byte[] mysteryPacketBytes = rs.getBytes("contents");
	    rs.close();
	    pstmt.close();
	    con.close();
	    
	    System.out.println("Here is the blob: ");
	    String contents = new String(mysteryPacketBytes);
	    System.out.println(contents);
	    

	    //now try the GridFTPPacketHandler on it:
	    myHandler = new GridFTPPacketHandler(dbdriver, dbURL, "gftp_packets");
	    buf = CustomByteBuffer.wrap(mysteryPacketBytes);
	    
	    maybePack = myHandler.instantiatePacket(buf);
	    Assert.assertTrue(maybePack instanceof GFTPTextPacket);
	    
	    buf.rewind();

	    maybePack.parseByteArray(mysteryPacketBytes);

	    //there is way too much back-and-forth: instantiatepacket wants
	    //a custombytebuffer but parsebytearray wants a byte[]?
	    //so we're going back and forth between the two for each packet
	    //instantiated..?
	    pack = (GFTPTextPacket)maybePack;

	    System.out.println("timstamp = "+pack.getTimestamp());
	    System.out.println("sender IP = "+pack.getHostIP());
	    System.out.println("StorOrRetr = "+pack.isStorOperation());
	    System.out.println("gridFTPVersion = "+pack.getGridFTPVersion());
	    System.out.println("StartTime = "+pack.getStartTime());
	    System.out.println("Endtime = "+pack.getEndTime());
	    System.out.println("numBytes = "+pack.getNumBytes());
	    System.out.println("numStripes = "+pack.getNumStripes());
	    System.out.println("numStreams = "+pack.getNumStreams());
	    System.out.println("bufferSize = "+pack.getBufferSize());
	    System.out.println("blockSize = "+pack.getBlockSize());
	    System.out.println("ftpReturnCode = "+pack.getFTPReturnCode());
	    
	    //Now let's write this guy to the gftprecords table:

	    myHandler.handlePacket(pack);
	    
	}
	catch (ClassNotFoundException cnfe) {
	    Assert.fail(cnfe.getMessage());
	}
	catch (SQLException e) {
	    Assert.fail(e.getMessage());
	}
    }

    public void testTrimmingPacket() {
	DatagramSocket outSock, inSock;
	DatagramPacket outPack, inPack;
	byte[] outData, inData, trimmedOutData;

	try {
	inSock = new DatagramSocket(4811);
	outSock = new DatagramSocket();
	outData = new byte[]{36, 24, 36};
	
	inData = new byte[1400];
	inPack = new DatagramPacket(inData, inData.length);
	outPack = new DatagramPacket(outData, 3);
	outPack.setPort(4811);
	outPack.setAddress(InetAddress.getByName("localhost"));
	outSock.send(outPack);
	inSock.receive(inPack);
	trimmedOutData = inPack.getData();
	System.out.println("Incoming packet has length "+ inPack.getLength());
	System.out.println("But its data buffer is "+ trimmedOutData.length);
	outSock.close();
	inSock.close();
	} catch (Exception e) {
	    Assert.fail("Socket experiment failed: "+e.getMessage());
	}
    }

    public static TestSuite suite() { 
	TestSuite suite= new TestSuite(); 
	//	suite.addTest(new UnitTester("testGFTPTextFormat"));
	suite.addTest(new UnitTester("testTrimmingPacket"));
	//suite.addTest(new TestSuite(SendReceiveTester.class));
		suite.addTest(new TestSuite(RingBufferTester.class));
	        suite.addTest(new TestSuite(ByteBufferTester.class));
	return suite;
    }

    //        suite.addTest(new TestSuite(GFTPRecordTester.class)); 

    public static void main(String args[]) {
        junit.textui.TestRunner.run(suite());
    }

}


