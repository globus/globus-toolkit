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

    public GridFTPPacketHandler(String driverClass, String db, String table) throws SQLException, ClassNotFoundException {
        super(driverClass, db, table);
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 0 && versionCode == 0);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
	//we must inspect the byte buffer to decide whether this is
	//GFTPMonitorPacket or GFTPTextPacket.
	//It would have been better to assign different packet version codes
	//to the two... but that requires changing the frozen code...
	//for a temporary kluge, I search for the string HOSTNAME.
	//But string search is an expensive call.
	if (new String(rawBytes.array()).indexOf("HOSTNAME") != -1) {
	    return new GFTPTextPacket();
	} else {
	    return new GFTPMonitorPacket();
	}
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{
        if (!(pack instanceof GFTPMonitorPacket)) {
            log.error("Something is seriously wrong: GridFTPPacketHandler got a packet which was not a GFTPMonitorPacket.");
            throw new SQLException("Can't happen.");
        }

        GFTPMonitorPacket gmp = (GFTPMonitorPacket)pack;
        
        return gmp.toSQL(con, table);
    }
}
