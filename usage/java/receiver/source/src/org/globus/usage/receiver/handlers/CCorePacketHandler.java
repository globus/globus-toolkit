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
	/*1 is the correct version code, but there are many installations
	out there that erroneously send packets with version code 4, and
	we want to catch both:*/
        return ((componentCode == 4 && (versionCode == 1 || versionCode == 4)) ||
                (componentCode == 1024 && versionCode == 256)); // little endian encoding
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
