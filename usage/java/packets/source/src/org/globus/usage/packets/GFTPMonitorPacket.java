package org.globus.usage.packets;

import java.net.Inet6Address;
import java.nio.ReadOnlyBufferException;
import java.sql.Timestamp;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/*Grid FTP monitor packets, in addition to the stuff in IPTimeMonitorPacket,
include the following:
      Component Executable version (dirt number, text)
      STOR or RETR (receiving or sending)
      start time of transfer
      end time of transfer
      number of bytes sent
      number of stripes
      number of streams
      TCP buffersize
      blocksize
      FTP return code
*/
public class GFTPMonitorPacket extends IPTimeMonitorPacket {

    static Log log = LogFactory.getLog(GFTPMonitorPacket.class);

    public final static byte STOR_CODE = 0;
    public final static byte RETR_CODE = 1;
    /*This fixes the number of bytes used to write the GridFTP version
      string:*/
    private final static int BYTES_FOR_VERSION = 20;

    public static short COMPONENT_CODE = 0;
    public static short VERSION_CODE = 0;

    private byte storOrRetr;
    private Date startTime, endTime;
    private long numBytes;
    private long numStripes, numStreams;
    private long bufferSize, blockSize;
    private long ftpReturnCode;
    private String gridFTPVersion;

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

    private short getIPVersion() {
        if (senderAddress instanceof Inet6Address)
            return 6;
        else
            return 4;
    }

    public void packCustomFields(CustomByteBuffer buf) {
        byte[] versionAsBytes;
        byte[] fixedNumberOfBytes = new byte[BYTES_FOR_VERSION];
        int i;

        super.packCustomFields(buf);

        versionAsBytes = gridFTPVersion.getBytes();
        /*Pad or truncate to the right number of bytes:*/
        for (i=0; i< BYTES_FOR_VERSION; i++) {
            if (versionAsBytes.length > i)
                fixedNumberOfBytes[i] = versionAsBytes[i];
        }
        buf.put(fixedNumberOfBytes);

        buf.put(storOrRetr);
        buf.putLong(startTime.getTime());
        buf.putLong(endTime.getTime());
        buf.putLong(numBytes);
        buf.putLong(numStripes);
        buf.putLong(numStreams);
        buf.putLong(bufferSize);
        buf.putLong(blockSize);
        buf.putLong(ftpReturnCode);

    }
   
    public void unpackCustomFields(CustomByteBuffer buf) {
        byte[] fixedNumberOfBytes = new byte[BYTES_FOR_VERSION];

        super.unpackCustomFields(buf);

        buf.get(fixedNumberOfBytes);
        gridFTPVersion = new String(fixedNumberOfBytes);

        storOrRetr = buf.get();
        startTime = new Date(buf.getLong());
        endTime = new Date(buf.getLong());
        numBytes = buf.getLong();
        numStripes = buf.getLong();
        numStreams  = buf.getLong();
        bufferSize = buf.getLong();
        blockSize = buf.getLong();
        ftpReturnCode = buf.getLong();
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
    }

    public String toSQL() {

        /*I'm sure this is a naiive way of making SQL... it works for
          now but should be replaced with something less brittle.*/
        return new String(
            " (component_code, version_code, send_time, ip_version, ip_address, gftp_version, stor_or_retr, start_time, end_time, num_bytes, num_stripes, num_streams, buffer_size, block_size, ftp_return_code) VALUES('" +
            getComponentCode() + "','" +
            getPacketVersion() + "','" +
            new Timestamp(timeSent).toString() + "','" +
            getIPVersion() + "','" +
            senderAddress.toString() + "','" +
            gridFTPVersion + "','" +
            storOrRetr + "','" +
            new Timestamp(startTime.getTime()).toString() + "','" +
            new Timestamp(endTime.getTime()).toString() + "','" +
            numBytes + "','" +
            numStripes + "','" +
            numStreams + "','" +
            bufferSize + "','" +
            blockSize + "','" +
            ftpReturnCode
            + "')");

    }
}
