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

import org.globus.usage.packets.CWSMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;

import java.sql.PreparedStatement;
import java.sql.SQLException;

/*Handler which writes GramUsageMonitor packets to database.*/
public class CCorePacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(CCorePacketHandler.class);

    public CCorePacketHandler(String dburl, String table) throws SQLException {
        super(dburl, table);
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 4 && versionCode == 1);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new CWSMonitorPacket();
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{
        if (!(pack instanceof CWSMonitorPacket)) {
            log.error("Can't happen.");
            throw new SQLException();
        }

        CWSMonitorPacket cPack= (CWSMonitorPacket)pack;
        return cPack.toSQL(this.con, this.table);
    }
}


/*What if we just had DefaultPacketHandler(packetClass, componentCode, versionCode, tablename)?*/
