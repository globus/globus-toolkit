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

import java.sql.SQLException;
import java.sql.PreparedStatement;

/*Handler which writes GridFTPPackets to database.*/
public class GridFTPPacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(GridFTPPacketHandler.class);

    public GridFTPPacketHandler(String db, String table) throws SQLException {
        super(db, table);
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 0 && versionCode == 0);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {

	return new GFTPTextPacket();
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{
        if (!(pack instanceof GFTPTextPacket)) {
            log.error("Something is seriously wrong: GridFTPPacketHandler got a packet which was not a GFTPMonitorPacket.");
            throw new SQLException("Can't happen.");
        }

        GFTPTextPacket gmp = (GFTPTextPacket)pack;
        
        return gmp.toSQL(con, table);
    }
}
