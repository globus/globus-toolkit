/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
