package org.globus.usage.packets;
import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.nio.ReadOnlyBufferException;
import java.sql.Timestamp;
import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Date;
import java.util.Calendar;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/*Another, text-based format for GFTP monitor packets.  The format
looks like this:
2 byte component code
2 byte format version code
16 byte ip address (if ipv4 the first 12 bytes will be 0)
4 byte timestamp
Then the following, as text, ending with newline:
HOSTNAME=mayed.mcs.anl.gov START=20050225024351.336329 END=20050225024351.395132 VER="0.17 (gcc32dbg, 1108765962-1)" BUFFER=16000 BLOCK=262144 NBYTES=5313 STREAMS=1 STRIPES=1 TYPE=RETR CODE=226 
*/
public class GFTPTextPacket extends GFTPMonitorPacket {

    static Log log = LogFactory.getLog(GFTPTextPacket.class);

    public void packCustomFields(CustomByteBuffer buf) {
	//nothing yet, sthis is only used for incoming packets...
	//but it will not call super.pack!!
    }
   
    public void unpackCustomFields(CustomByteBuffer buf) {
	byte[] ipBytes = new byte[16];
	String ipString;
	String contents;
	PacketFieldParser parser;

	//dont' call super.unpack!!
       
	//component and version codes have already been read for us
	buf.getBytes(ipBytes);
	ipString  = new String(ipBytes);

	//this is redundant with the hostname given in the text, and I trust that one more
	/*	log.info("Here's the IP I'm getting from packet: "+ipString);
	try {
	    this.senderAddress = 
		InetAddress.getByAddress(ipBytes);
	} catch (UnknownHostException uhe) {
	    this.senderAddress = null;
	    }*/

	//there's supposed to be 4-byte timestamp...
	//shouldn't it be 8??
	setTimestamp((long)buf.getInt());

	/*Now we get to the text:
HOSTNAME=mayed.mcs.anl.gov START=20050225073026.426286 END=20050225073026.560613 VER="0.17 (gcc32dbg, 1108765962-1)" BUFFER=16000 BLOCK=262144 NBYTES=504 STREAMS=1 STRIPES=1 TYPE=RETR CODE=226
	*/

	try {
	    contents = new String(buf.getRemainingBytes());
	    parser = new PacketFieldParser(contents);
	    
	    try {
		senderAddress = InetAddress.getByName(parser.getString("HOSTNAME"));
	    } catch (UnknownHostException uhe) {}
	    
	    startTime = dateFromLogfile(parser.getString("START"));
	    endTime = dateFromLogfile(parser.getString("END"));
	    
	    gridFTPVersion = parser.getString("VER");
	    
	    bufferSize = parser.getLong("BUFFER");
	    blockSize = parser.getLong("BLOCK");
	    numBytes = parser.getLong("NBYTES");
	    numStreams = parser.getLong("STREAMS");
	    numStripes = parser.getLong("STRIPES");
	    
	    String temp = parser.getString("TYPE");
	    if (temp.equals("STOR") || temp.equals("ESTO"))
		storOrRetr = STOR_CODE;
	    else if (temp.equals("RETR") || temp.equals("ERET"))
		storOrRetr = RETR_CODE;
	    else {
		storOrRetr = OTHER_TYPE_CODE;
	    }
	    
	    ftpReturnCode = parser.getLong("CODE"); 
	}
	catch (Exception e) {
	    //do logger error output when I get a packet I totally can't parse, and
	    //dump out its whole string for analysis.
	    e.printStackTrace();
	    log.error(e.getMessage());
	    log.error(new String(buf.array()));
	}
    }

     private Date dateFromLogfile(String logfileEntry) {
        int year, month, day, hour, minute, second;
        float millis;
        Calendar temp;

        /*Date format used in log files has fixed-width fields, so
          I can do this the easy way; this is however brittle if logfile format changes.*/
        year = 2000 + Integer.parseInt(logfileEntry.substring(3,4));
        /*Calendar uses 0-based indexing for months; logfiles use 1-based indexing.*/
        month = Integer.parseInt(logfileEntry.substring(4,6)) - 1;
        day = Integer.parseInt(logfileEntry.substring(6,8));
        hour = Integer.parseInt(logfileEntry.substring(8,10));
        minute = Integer.parseInt(logfileEntry.substring(10,12));
        second = Integer.parseInt(logfileEntry.substring(12,14));
        //substring with one arg gets from there till end of string
        millis = 1000*Float.parseFloat("0"+logfileEntry.substring(14));
        /*In some cases the microseconds may actually be less than six digits.*/
        temp = Calendar.getInstance();
        temp.set(year, month, day, hour, minute, second);
        /*Constructor can't take milliseconds, so here's how I adjust it to milliseconds:*/
        temp.set(Calendar.MILLISECOND, (int)Math.round(millis));
        return temp.getTime();
    }

}
