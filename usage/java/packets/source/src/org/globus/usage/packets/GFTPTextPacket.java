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
        byte[] fixedNumberOfBytes = new byte[BYTES_FOR_VERSION];
	byte[] ipBytes = new byte[16];
	String ipString;
	String contents = new String(buf.array());
	String trimmedString, moreString;
	int index1, index2;
        String[] fields;
	String[] temp;

	//dont' call super.unpack!!
       
	//component and version codes have already been read for us
	buf.getBytes(ipBytes);
	ipString  = new String(ipBytes);

	log.info("Here's the IP I'm getting from packet: "+ipString);
	try {
	    this.senderAddress = 
		InetAddress.getByAddress(ipBytes);
	} catch (UnknownHostException uhe) {
	    log.warn("This packet came from a host I can't identify");
	    this.senderAddress = null;
	}

	//there's supposed to be 4-byte timestamp...
	//shouldn't it be 8??
	setTimestamp((long)buf.getInt());

	/*Now we get to the text:
HOSTNAME=mayed.mcs.anl.gov START=20050225073026.426286 END=20050225073026.560613 VER="0.17 (gcc32dbg, 1108765962-1)" BUFFER=16000 BLOCK=262144 NBYTES=504 STREAMS=1 STRIPES=1 TYPE=RETR CODE=226
	*/

	try {
	    /*Locate the substrings that begin with HOSTNAME and BUFFER.
	      There is binary data before HOSTNAME that we don't want to try to parse here.*/
	    index1 = contents.indexOf("HOSTNAME");
	    if (index1 == -1) {
		throw new Exception("Packet doesn't contain HOSTNAME.");
	    }
	    index2 = contents.indexOf("BUFFER", index1+1);
	    if (index2 == -1) {
		throw new Exception("Packet doesn't contain BUFFER.");
	    }
	    trimmedString = contents.substring(index1+1, index2);
	    moreString = contents.substring(index2);


	    /*Find the quoted section -- make sure to start after HOSTNAME to avoid
	     false matches on binary data that looks like a quote.*/
	    index1 = contents.indexOf("\"", index1); 
	    if (index1 == -1) {
		throw new Exception("Packet doesn't contain quoted section.");
	    }
	    index2 = contents.indexOf("\"", index1+1);
	    if (index2 == -1) {
		throw new Exception("Packet doesn't contain quoted section.");
	    }
	    //gridftp version is the string between the quotes.
	    gridFTPVersion = contents.substring(index1+1, index2);
	    fields = trimmedString.split(" ");
	    if (fields.length < 4) {
		throw new Exception("Two few fields in the line.");
	    }


	    temp = fields[0].split("=");
	    hostname = temp[1]; //hostname is after first equals sign
	    senderAddress = InetAddress.getByName(hostname);

	    temp = fields[1].split("=");
	    startTime = dateFromLogfile(temp[1]); //start date after next equals

	    temp = fields[2].split("=");
	    endTime = dateFromLogfile(temp[1]); //end date

	    fields = moreString.split(" ");
	    if (fields.length < 7) {
		throw new Exception("Two few fields in the line.");
	    }

	    temp = fields[0].split("=");
	    bufferSize = Long.parseLong(temp[1]);
	    temp = fields[1].split("=");
	    blockSize = Long.parseLong(temp[1]);  
	    temp = fields[2].split("=");
	    numBytes = Long.parseLong(temp[1]);
	    temp = fields[3].split("=");
	    numStreams = Long.parseLong(temp[1]);
	    temp = fields[4].split("=");
	    numStripes = Long.parseLong(temp[1]);
	    temp = fields[5].split("=");
	    if (temp[1].equals("STOR") || temp[1].equals("ESTO"))
		storOrRetr = STOR_CODE;
	    else if (temp[1].equals("RETR") || temp[1].equals("ERET"))
		storOrRetr = RETR_CODE;
	    else
		throw new Exception("Neither STOR nor RETR.");

	    temp = fields[6].split("=");
	    ftpReturnCode = Long.parseLong(temp[1]); 

	}
	catch (Exception e) {
	    //do logger error output when I get a packet I totally can't parse, and
	    //dump out its whole string for analysis.
	    e.printStackTrace();
	    log.error(e.getMessage());
	    log.error(contents);
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
