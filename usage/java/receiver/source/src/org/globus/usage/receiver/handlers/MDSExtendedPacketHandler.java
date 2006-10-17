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
import org.globus.usage.packets.MDSExtendedMonitorPacket;
import org.globus.usage.packets.UsageMonitorPacket;

import java.sql.PreparedStatement;
import java.sql.SQLException;

public class MDSExtendedPacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(MDSExtendedPacketHandler.class);

    public MDSExtendedPacketHandler(String dburl, String table) throws SQLException {
        super(dburl, table);
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 7 && versionCode == 0);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new MDSExtendedMonitorPacket();
    }
   
    protected PreparedStatement makeSQLInsert(UsageMonitorPacket packet) throws SQLException{
        if (!(packet instanceof MDSExtendedMonitorPacket)) {
            log.error("Invalid Packet Type: expected MDSExtendedMonitorPacket");
            throw new SQLException();
        }

        MDSExtendedMonitorPacket mds = (MDSExtendedMonitorPacket)packet;

        return mds.toSQL(this.con, this.table);
    }
}
