package org.globus.usage.receiver.handlers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.exec.service.usage.GramUsageMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;

import java.sql.PreparedStatement;
import java.sql.SQLException;

/*Handler which writes GramUsageMonitor packets to database.*/
public class GRAMPacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(RFTPacketHandler.class);

    public GRAMPacketHandler(String dburl, String table) throws SQLException {
        super(dburl, table);
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 5 && versionCode == 1);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new GramUsageMonitorPacket();
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{
        if (!(pack instanceof GramUsageMonitorPacket)) {
            log.error("Can't happen.");
            throw new SQLException();
        }

        GramUsageMonitorPacket gramPack= (GramUsageMonitorPacket)pack;
        
        return gramPack.toSQL(this.con, this.table);
    }
}
