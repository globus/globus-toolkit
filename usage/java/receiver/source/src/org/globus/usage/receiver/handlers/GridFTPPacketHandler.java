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
import org.globus.usage.packets.GFTPTextPacket;
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.usage.packets.Util;

import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Timestamp;

import java.util.Properties;


/*Handler which writes GridFTPPackets to database.*/
public class GridFTPPacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(GridFTPPacketHandler.class);

    private long mcsPacketCount, externalPacketCount;

    private String[] domainsToFilter;
    private String tableForMCS, tableForOther;
    private static final String newline = System.getProperty("line.separator");

    private static final String connectionPoolName = "jdbc:apache:commons:dbcp:usagestats";

    public GridFTPPacketHandler(Properties props)
    throws SQLException
    {
        super(props.getProperty("database-pool"),
              props.getProperty("gftp-table", "gftp_packets"));

        this.tableForMCS = props.getProperty("gftp-filtered-out-table",
                                             "mcs_internal_gftp_packets");
        this.tableForOther = props.getProperty("gftp-table", "gftp_packets");
        String domains = props.getProperty("gftp-filter-domains",
                                           "mcs.anl.gov,isi.edu");
	this.domainsToFilter = domains.split(",");
	System.out.println("Filtering out GFTP packets from ");
	for (int i=0; i<this.domainsToFilter.length; i++) {
	    System.out.println(this.domainsToFilter[i]);
	}
	System.out.println("Into table " + tableForMCS);

	this.mcsPacketCount = this.externalPacketCount = 0;
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 0 && versionCode == 0);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
	return new GFTPTextPacket();
    }

    public void resetCounts() {
	mcsPacketCount = externalPacketCount = 0;
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
	return output.toString();
    }

    public void handlePacket(UsageMonitorPacket pack) {
	/*We do two things with each UsageMonitorPacket: we wrpite it
	  to the database, and if it's not an internal-to-MCS packet, we also
	  update an AggregateSummary that we keep around, and add to the daily
	  packet count...*/

	GFTPTextPacket gftp = (GFTPTextPacket)pack;

        //GFTPRecord record = convertToRecord(gftp);

	String hostname = gftp.getHostIP().toString();
	
	if (gftp.isInDomain(domainsToFilter)) {
	    this.mcsPacketCount ++;
	    writePacketToTable(pack, this.tableForMCS);
	}
	else  {
	    this.externalPacketCount ++;
	    writePacketToTable(pack, this.tableForOther);
	}
    }

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

	PreparedStatement ps;
	StringBuffer sqlContents = new StringBuffer();
	sqlContents.append("INSERT INTO ");
	sqlContents.append(table);
	sqlContents.append(" (component_code, version_code, send_time, ip_version, hostname, gftp_version, stor_or_retr, start_time, end_time, num_bytes, num_stripes, num_streams, buffer_size, block_size, ftp_return_code, loaded_dsi, event_modules, access_schema, client_app, client_appver, file_name, client_ip, data_ip, user_name, user_dn, conf_id, session_id, ip_address )");
	sqlContents.append(" VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
	ps = con.prepareStatement(sqlContents.toString());

	ps.setShort(1, gmp.getComponentCode());
	ps.setShort(2, gmp.getPacketVersion());
	ps.setTimestamp(3, new Timestamp(gmp.getTimestamp()));
	ps.setByte(4, gmp.getIPVersion());
        ps.setString(5, Util.getAddressAsString(gmp.getHostIP()));
	ps.setString(6, gmp.getGridFTPVersion());
	ps.setByte(7, gmp.isStorOperation() ? gmp.STOR_CODE : gmp.RETR_CODE);
	if (gmp.getStartTime() == null)
	    ps.setLong(8, 0L);
	else
	    ps.setTimestamp(8, new Timestamp(gmp.getStartTime().getTime()));
	if (gmp.getEndTime() == null)
	    ps.setLong(9, 0L);
	else
	    ps.setTimestamp(9, new Timestamp(gmp.getEndTime().getTime()));
	ps.setLong(10, gmp.getNumBytes());
	ps.setLong(11, gmp.getNumStripes());
	ps.setLong(12, gmp.getNumStreams());
	ps.setLong(13, gmp.getBufferSize());
	ps.setLong(14, gmp.getBlockSize());
	ps.setLong(15, gmp.getFTPReturnCode());
        ps.setString(16, gmp.getLoadedDSI());	
        ps.setString(17, gmp.getEventModules());	
        ps.setString(18, gmp.getAccessSchema());	
        ps.setString(19, gmp.getClientApp());	
        ps.setString(20, gmp.getClientAppver());	
        ps.setString(21, gmp.getFileName());	
        ps.setString(22, gmp.getClientIP());	
        ps.setString(23, gmp.getDataIP());	
        ps.setString(24, gmp.getUserName());	
        ps.setString(25, gmp.getUserDN());	
        ps.setString(26, gmp.getConfID());	
        ps.setString(27, gmp.getSessionID());	
        ps.setString(28, gmp.getHostIP().getHostAddress());	
	return ps;
    }
}
