/*
 * This file or a portion of this file is licensed under the terms of the
 * Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without modifications,
 * you must include this notice in the file.
 */
package org.globus.usage.receiver.handlers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.wsrf.container.usage.ContainerUsageBasePacket;
import org.globus.wsrf.container.usage.ContainerUsageStartPacket;
import org.globus.wsrf.container.usage.ContainerUsageStopPacket;


import java.sql.SQLException;
import java.sql.PreparedStatement;



/*Handler which writes GridFTPPackets to database.*/
public class JavaCorePacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(JavaCorePacketHandler.class);

    public JavaCorePacketHandler(String db, String table) throws SQLException {
        super(db, table);
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 3) &&
	    (versionCode == 1);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {

	/*Todo: it's going to have to look inside the rawBytes to see
	  whether to instantiate StartPacket (eventType == START_EVENT)
	  or StopPacket (eventType == STOP_EVENT).*/
	return new JavaCorePacket();
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{
        if (!(pack instanceof JavaCoreMonitorPacket)) {
	    throw new SQLException("Can't happen.");
        }

        /*The stuff that needs to go into the database here is as follows:
	  for both types:
	  containerID INT,
	  containerType SMALLINT,
	  eventType SMALLINT
	for startPacket:
	  a very long String list
	 */
        
        return jcp.toSQL(con, table);
    }
}
