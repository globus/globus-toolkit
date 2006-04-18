/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

package org.globus.usage.receiver.handlers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.GFTPMonitorPacket;
import org.globus.usage.packets.GFTPTextPacket;
import org.globus.usage.packets.UsageMonitorPacket;

import java.util.Date;
import java.util.Calendar;
import java.util.TimeZone;

import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.DriverManager;

import org.globus.cog.monitor.guss.HourSummary;
import org.globus.cog.monitor.guss.KnownHosts;
import org.globus.cog.monitor.guss.AggregateSummary;
import org.globus.cog.monitor.guss.GFTPRecord;
import org.globus.cog.monitor.guss.HistogramBucketArray;

/*Handler which writes GridFTPPackets to database.*/
public class GridFTPPacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(GridFTPPacketHandler.class);

    private long mcsPacketCount, externalPacketCount;

    /*
    private long longestDelay;
    private HistogramBucketArray delayHistogram;
    private HourSummary runningSummary;
    private AggregateSummary dailySummary;
    private Date startOfHour;
    */

    private String[] domainsToFilter;
    private String tableForMCS, tableForOther;
    private static final String newline = System.getProperty("line.separator");

    //private static final long MILLISECONDS_IN_HOUR = 3600000;
    private static final String connectionPoolName = "jdbc:apache:commons:dbcp:usagestats";

    public GridFTPPacketHandler(String db, String tableForMCS, String tableForOther,
				String domains) throws SQLException {

        super(db, tableForOther);
	this.domainsToFilter = domains.split(",");
	System.out.println("Filtering out GFTP packets from ");
	for (int i=0; i<this.domainsToFilter.length; i++) {
	    System.out.println(this.domainsToFilter[i]);
	}
	System.out.println("Into table " + tableForMCS);

	this.tableForMCS = tableForMCS;
	this.tableForOther = tableForOther;
	this.mcsPacketCount = this.externalPacketCount = 0;

        /*
	this.startOfHour = roundDateDownToHour();
	this.runningSummary = new HourSummary(this.startOfHour);
	this.dailySummary = new AggregateSummary(this.startOfHour);
	this.longestDelay = 0;
	this.delayHistogram = new HistogramBucketArray(new double[] {-7.0*MILLISECONDS_IN_HOUR, -6.0*MILLISECONDS_IN_HOUR, -5.0*MILLISECONDS_IN_HOUR, -4.0*MILLISECONDS_IN_HOUR, -3.0*MILLISECONDS_IN_HOUR, -7200000.0, -3600000.0, -600000.0, -60000.0, -10000.0, -1000.0, -100.0, 0, 100.0, 1000.0, 10000.0, 60000.0, 600000.0, 3600000.0});
        */

	Connection con = DriverManager.getConnection(connectionPoolName);
	KnownHosts.readFromDatabase(con);
	con.close();
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 0 && versionCode == 0);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
	return new GFTPTextPacket();
    }

    public void resetCounts() {
	mcsPacketCount = externalPacketCount = 0;
	//runningSummary = new HourSummary(new Date());
    }

    public String getStatus() {
	StringBuffer output = new StringBuffer();
	output.append("GridFTP Transfers: ");
	output.append(newline);
	output.append("  Internal to MCS: ");
	output.append(mcsPacketCount);
	output.append(newline);
	output.append("  External to MCS: ");
	output.append(externalPacketCount);
	output.append(newline);
        /*
	output.append("  Outside of MCS, there were ");
	output.append(dailySummary.getNumHosts());
	output.append(" hosts, ");
	output.append(dailySummary.getNumNewHosts());
	output.append(" of them not seen before, in the following top-level domains: ");
	output.append(dailySummary.getCountries());
	output.append(newline);
	output.append("  Longest delay between completion of transfer and receipt of packet: ");
	output.append(longestDelay);
	output.append("  Delay Histogram: ");
	output.append(delayHistogram.toString());
	output.append(newline);
        */
	return output.toString();
    }

    /*org.globus.usage.packets.GFTPTextPacket and org.globus.cog.monitor.guss.GFTPRecord represent
      basically the same thing; this converts the former to the latter:*/
    private org.globus.cog.monitor.guss.GFTPRecord convertToRecord(GFTPTextPacket packet) {
	byte storeOrRetrByte = (byte)(packet.isStorOperation()?0:1);
	return new GFTPRecord(packet.getStartTime(), packet.getEndTime(), packet.getHostIP().toString(), 
			      storeOrRetrByte, packet.getNumBytes(), packet.getNumStripes(),
			      packet.getNumStreams(), packet.getBufferSize(), packet.getBlockSize(), 
			      packet.getFTPReturnCode(), packet.getGridFTPVersion());
	
    }
   
    public void handlePacket(UsageMonitorPacket pack) {
	/*We do two things with each UsageMonitorPacket: we wrpite it
	  to the database, and if it's not an internal-to-MCS packet, we also
	  update an AggregateSummary that we keep around, and add to the daily
	  packet count...*/

	GFTPTextPacket gftp = (GFTPTextPacket)pack;
        GFTPRecord record = convertToRecord(gftp);

	String hostname = gftp.getHostIP().toString();
	
	if (gftp.isInDomain(domainsToFilter)) {
	    this.mcsPacketCount ++;
	    writePacketToTable(pack, this.tableForMCS);
	}
	else  {

            /*
	    //Check current date against startOfHour to see whether we should start a new 
	    //hourly summary:
	    Date now = new Date();
	    if (now.getTime() - this.startOfHour.getTime() > MILLISECONDS_IN_HOUR) {
		hourlyDatabaseUpdate();
	    }
	    //Compare current time with the time of transfer completion in the packet.
	    //keep track of the variances in these.
	    long delay = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTime().getTime() - record.getEndTime();
	    delayHistogram.sortValue(delay);
	    if (Math.abs(delay) > Math.abs(longestDelay)) {
		this.longestDelay = delay;
	    }
	    //update summary with packet
	    this.runningSummary.addRecord(record);
            */

	    this.externalPacketCount ++;
	    writePacketToTable(pack, this.tableForOther);
	}
    }

    /*
    private void hourlyDatabaseUpdate() {
	Connection con = null;
	try {
	    con = DriverManager.getConnection(connectionPoolName);
	    runningSummary.storeToDB(con);
	    log.info("Did the hourly write-to-database");
	    //this will call KnownHosts.writeToDatabase
	}
	catch (SQLException e) {
	    System.out.println("Problem writing summary to database! " + e.getMessage());
	}
	try {
	    con.close();
	} catch (SQLException e) {
	}

	dailySummary.addSummary(runningSummary);
	startOfHour = roundDateDownToHour();
	runningSummary = new HourSummary(startOfHour);
    }

    private Date roundDateDownToHour() {
	Calendar temp = Calendar.getInstance();
	temp.set(Calendar.MINUTE, 0);
	temp.set(Calendar.SECOND, 0);
	temp.set(Calendar.MILLISECOND, 0);
	return temp.getTime();
    }
    */

    /*Rewrite the following two methods to eliminate the callback into super.handlePacket*/
    private void writePacketToTable(UsageMonitorPacket pack, String tablename) {
	this.table = tablename;
	super.handlePacket(pack);
    }

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{
        if (!(pack instanceof GFTPTextPacket)) {
            log.error("Something is seriously wrong: GridFTPPacketHandler got a packet which was not a GFTPMonitorPacket.");
            throw new SQLException("Can't happen.");
        }

        GFTPTextPacket gmp = (GFTPTextPacket)pack;
        return gmp.toSQL(con, table);
    }
}
