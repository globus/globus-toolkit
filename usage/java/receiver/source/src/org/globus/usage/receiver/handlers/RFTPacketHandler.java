package org.globus.usage.receiver.handlers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.transfer.reliable.service.usage.RFTUsageMonitorPacket;
import org.globus.usage.packets.UsageMonitorPacket;

/*Handler which writes RFTUsageMonitor packets to database.*/
public class RFTPacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(GridFTPPacketHandler.class);

    public RFTPacketHandler(String driverClass, String db, String table) {
        super(driverClass, db, table);
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 5 && versionCode == 1);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new RFTUsageMonitorPacket();
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected String makeSQLInsert(UsageMonitorPacket pack) {
        if (!(pack instanceof RFTUsageMonitorPacket)) {
            log.error("Something is seriously wrong: RFTUsageMonitorPacket got a packet which was not a RFTUsageMonitorPacket.");
            return "";
        }

        RFTUsageMonitorPacket rft= (RFTUsageMonitorPacket)pack;
        
        return rft.toSQL();
    }
}
