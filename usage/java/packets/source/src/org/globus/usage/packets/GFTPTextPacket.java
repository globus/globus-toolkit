/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.globus.usage.packets;

import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.UnknownHostException;
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
public class GFTPTextPacket extends CStylePacket {

    static Log log = LogFactory.getLog(GFTPTextPacket.class);

    public final static byte STOR_CODE = 0;
    public final static byte RETR_CODE = 1;
    public final static byte OTHER_TYPE_CODE = 2;

    public static short COMPONENT_CODE = 0;
    public static short VERSION_CODE = 0;

    protected byte storOrRetr;
    protected Date startTime, endTime;
    protected long numBytes;
    protected long numStripes, numStreams;
    protected long bufferSize, blockSize;
    protected long ftpReturnCode;
    protected String gridFTPVersion;
    protected String hostname;
    protected String loadedDSI;
    protected String eventModules;
    protected String accessSchema;
    protected String clientApp;
    protected String clientAppver;
    protected String fileName;
    protected String clientIP;
    protected String dataIP;
    protected String userName;
    protected String userDN;
    protected String confID;
    protected String sessionID;


    public boolean isStorOperation() {
        return storOrRetr == STOR_CODE;
    }
    public boolean isRetrOperation() {
        return storOrRetr == RETR_CODE;
    }
    public Date getStartTime() {
        return startTime;
    }
    public Date getEndTime() {
        return endTime;
    }
    public long getNumBytes() {
        return numBytes;
    }
    public long getNumStripes() {
        return numStripes;
    }
    public long getNumStreams() {
        return numStreams;
    }
    public long getBufferSize() {
        return bufferSize;
    }
    public long getBlockSize() {
        return blockSize;
    }
    public long getFTPReturnCode() {
        return ftpReturnCode;
    }
    public String getGridFTPVersion() {
        return gridFTPVersion;
    }
    public String getLoadedDSI() {
        return loadedDSI;
    }
    public String getEventModules() {
        return eventModules;
    }
    public String getAccessSchema() {
        return accessSchema;
    }
    public String getClientApp() {
        return clientApp;
    }
    public String getClientAppver() {
        return clientAppver;
    }
    public String getFileName() {
        return fileName;
    }
    public String getClientIP() {
        return clientIP;
    }
    public String getDataIP() {
        return dataIP;
    }
    public String getUserName() {
        return userName;
    }
    public String getUserDN() {
        return userDN;
    }
    public String getConfID() {
        return confID;
    }
    public String getSessionID() {
        return sessionID;
    }

    public void setOperationType (byte newType) {
        storOrRetr = newType;
    }
    public void setStartTime(Date st) {
         startTime = st;
    }
    public void setEndTime(Date et) {
         endTime = et;
    }
    public void setNumBytes(long nb) {
         numBytes = nb;
    }
    public void setNumStripes(long ns) {
         numStripes = ns;
    }
    public void setNumStreams(long ns) {
         numStreams = ns;
    }
    public void setBufferSize(long bs) {
         bufferSize = bs;
    }
    public void setBlockSize(long bs) {
         blockSize = bs;
    }
    public void setFTPReturnCode(long ftp) {
         ftpReturnCode = ftp;
    }
    public void setGridFTPVersion(String v) {
        gridFTPVersion = v;
    }
    public void setLoadedDSI(String x) {
        loadedDSI = x;
    }
    public void setEventModules(String x) {
        eventModules = x;
    }
    public void setAccessSchema(String x) {
        accessSchema = x;
    }
    public void setClientApp(String x) {
        clientApp = x;
    }
    public void setClientAppver(String x) {
        clientAppver = x;
    }
    public void setFileName(String x) {
        fileName = x;
    }
    public void setClientIP(String x) {
        clientIP = x;
    }
    public void setDataIP(String x) {
        dataIP = x;
    }
    public void setUserName(String x) {
        userName = x;
    }
    public void setUserDN(String x) {
        userDN = x;
    }
    public void setConfID(String x) {
        confID = x;
    }
    public void setSessionID(String x) {
        sessionID = x;
    }

    public boolean isInDomain(String[] domainList) {
	/*TODO: Move to base class -- should be able to do on any packet type*/
	String ipAsString = senderAddress.toString();
	
	for (int i= 0; i<domainList.length; i++) {
	    if (ipAsString.indexOf(domainList[i]) != -1) {
		return true;
	    }
	}
	return false;
    }

    public void packCustomFields(CustomByteBuffer buf) {
	//nothing yet, sthis is only used for incoming packets...
	//but it will not call super.pack!!
    }
   
    public void unpackCustomFields(CustomByteBuffer buf) {

	super.unpackCustomFields(buf);

	/*Now we get to the text.  Example:
HOSTNAME=mayed.mcs.anl.gov START=20050225073026.426286 END=20050225073026.560613 VER="0.17 (gcc32dbg, 1108765962-1)" BUFFER=16000 BLOCK=262144 NBYTES=504 STREAMS=1 STRIPES=1 TYPE=RETR CODE=226
	*/

	try {
	    PacketFieldParser parser = parseTextSection(buf);
	    
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
            loadedDSI = parser.getString("DSI");
            eventModules = parser.getString("EM");
            accessSchema = parser.getString("SCHEMA");
            clientApp = parser.getString("APP");
            clientAppver = parser.getString("APPVER");
            fileName = parser.getString("FILE");
            clientIP = parser.getString("CLIENTIP");
            dataIP = parser.getString("DATAIP");
            userName = parser.getString("USER");
            userDN = parser.getString("USERDN");
            confID = parser.getString("CONFID");
            sessionID = parser.getString("SESSID");
	   
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

    public void display() {
        log.info(super.toString());
        log.info("StorOrRetr = "+storOrRetr);
        log.info("gridFTPVersion = "+gridFTPVersion);
        log.info("StartTime = "+startTime);
        log.info("Endtime = "+endTime);
        log.info("numBytes = "+numBytes);
        log.info("numStripes = "+numStripes);
        log.info("numStreams = "+numStreams);
        log.info("bufferSize = "+bufferSize);
        log.info("blockSize = "+blockSize);
        log.info("ftpReturnCode = "+ftpReturnCode);
        log.info("loadedDSI = "+loadedDSI);
        log.info("eventModules = "+eventModules);
        log.info("accessSchema = "+accessSchema);
        log.info("clientApp = "+clientApp);
        log.info("clientAppver = "+clientAppver);
        log.info("fileName = "+fileName);
        log.info("clientIP = "+clientIP);
        log.info("dataIP = "+dataIP);
        log.info("userName = "+userName);
        log.info("userDN = "+userDN);
        log.info("confID = "+confID);
        log.info("sessionID = "+sessionID);
    }
    /*returns 4 if this is IPv4, 6 if this is IPv6.*/
    public byte getIPVersion() {
	if (senderAddress == null) {
	    return 4;
	}
	if (senderAddress instanceof Inet6Address) {
	    return 6;
	} else {
	    return 4;
	}
    }
}
