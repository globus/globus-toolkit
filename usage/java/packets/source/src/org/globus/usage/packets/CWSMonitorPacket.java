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

public class CWSMonitorPacket extends CStylePacket {

    public void unpackCustomFields(CustomByteBuffer buf) {
	super.unpackCustomFields(buf);
	PacketFieldParser parser = parseTextSection(buf);
	try {
	    this.senderAddress = InetAddress.getByName(parser.getString("HOSTNAME"));
	} catch (UnknownHostException uhe) {}

    }

    public PreparedStatement toSQL(Connection con, String tablename) throws SQLException {
	PreparedStatement ps;
	ps = con.prepareStatement("INSERT INTO "+tablename+" (component_code, version_code, send_time, ip_address) VALUES (?, ?, ?, ?);");
	
	ps.setShort(1, this.getComponentCode());
	ps.setShort(2, this.getPacketVersion());
	ps.setTimestamp(3, new Timestamp(this.getTimestamp()));
	ps.setString(4, this.getHostIP().toString());

	return ps;
    }

}
