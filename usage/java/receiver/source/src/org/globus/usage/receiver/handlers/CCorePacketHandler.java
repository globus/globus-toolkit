package org.globus.usage.receiver.handlers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.GramUsageMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;

import java.sql.PreparedStatement;
import java.sql.SQLException;

/*Handler which writes GramUsageMonitor packets to database.*/
public class CCorePacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(CCorePacketHandler.class);

    public GRAMPacketHandler(String dburl, String table) throws SQLException {
        super(dburl, table);
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 4 && versionCode == 4);
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
