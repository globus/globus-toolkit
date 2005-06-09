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
import org.globus.usage.packets.RFTUsageMonitorPacket;
//import org.globus.transfer.reliable.service.usage.RFTUsageMonitorPacket;
import org.globus.usage.packets.UsageMonitorPacket;

import java.sql.PreparedStatement;
import java.sql.SQLException;

/*Handler which writes RFTUsageMonitor packets to database.*/
public class RFTPacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(RFTPacketHandler.class);

    public RFTPacketHandler(String dburl, String table) throws SQLException {
        super(dburl, table);
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 5 && versionCode == 1);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new RFTUsageMonitorPacket();
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{
        if (!(pack instanceof RFTUsageMonitorPacket)) {
            log.error("Something is seriously wrong: RFTUsageMonitorPacket got a packet which was not a RFTUsageMonitorPacket.");
            throw new SQLException();
        }

        RFTUsageMonitorPacket rft= (RFTUsageMonitorPacket)pack;
        
        return rft.toSQL(this.con, this.table);
    }
}
