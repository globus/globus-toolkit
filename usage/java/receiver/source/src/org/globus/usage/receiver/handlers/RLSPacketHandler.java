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

import org.globus.usage.packets.RLSMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;

import java.sql.PreparedStatement;
import java.sql.SQLException;

/*Handler which writes GramUsageMonitor packets to database.*/
public class RLSPacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(RLSPacketHandler.class);

    public RLSPacketHandler(String dburl, String table) throws SQLException {
        super(dburl, table);
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return ((componentCode == 7 && (versionCode == 0 || versionCode == 7)) ||
                (componentCode == 1792 && versionCode == 0)); // little endian encoding
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new RLSMonitorPacket();
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{
        if (!(pack instanceof RLSMonitorPacket)) {
            log.error("Can't happen.");
            throw new SQLException();
        }

        RLSMonitorPacket rlsPack= (RLSMonitorPacket)pack;
        
        return rlsPack.toSQL(this.con, this.table);
    }
}
