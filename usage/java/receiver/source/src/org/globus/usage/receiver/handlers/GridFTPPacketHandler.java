package org.globus.usage.receiver.handlers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.GFTPMonitorPacket;
import org.globus.usage.packets.UsageMonitorPacket;

/*Handler which writes GridFTPPackets to database.*/
public class GridFTPPacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(GridFTPPacketHandler.class);

    public GridFTPPacketHandler(String driverClass, String db, String table) {
        super(driverClass, db, table);
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 0 && versionCode == 0);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new GFTPMonitorPacket();
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected String makeSQLInsert(UsageMonitorPacket pack) {
        if (!(pack instanceof GFTPMonitorPacket)) {
            log.error("Something is seriously wrong: GridFTPPacketHandler got a packet which was not a GFTPMonitorPacket.");
            return "";
        }

        GFTPMonitorPacket gmp = (GFTPMonitorPacket)pack;
        
        return gmp.toSQL();
    }
}
