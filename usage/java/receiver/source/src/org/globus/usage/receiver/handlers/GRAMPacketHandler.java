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

import org.globus.usage.packets.GramUsageMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.usage.packets.Util;

import java.util.Properties;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;

/*Handler which writes GramUsageMonitor packets to database.*/
public class GRAMPacketHandler extends DefaultPacketHandler {

    private static Log log = LogFactory.getLog(GRAMPacketHandler.class);

    public GRAMPacketHandler(Properties props) throws SQLException {
        super(props.getProperty("database-pool"),
              props.getProperty("gram-table", "gram_packets"));
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return (componentCode == 1 && versionCode == 1);
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new GramUsageMonitorPacket();
    }
   
    //uses DefaultPacketHandler's handlePacket().

    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{
        if (!(pack instanceof GramUsageMonitorPacket)) {
            log.error("Packet Type Mismatch");
            throw new SQLException();
        }

        GramUsageMonitorPacket gramPack = (GramUsageMonitorPacket) pack;

	PreparedStatement ps;

	ps = con.prepareStatement("INSERT INTO "+table+" (component_code, version_code, send_time, ip_address, creation_time, scheduler_type, job_credential_endpoint_used, file_stage_in_used, file_stage_out_used, file_clean_up_used, clean_up_hold_used, job_type, gt2_error_code, fault_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
	
	ps.setShort(1, gramPack.getComponentCode());
	ps.setShort(2, gramPack.getPacketVersion());
	ps.setTimestamp(3, new Timestamp(gramPack.getTimestamp()));
        ps.setString(4, Util.getAddressAsString(gramPack.getHostIP()));
	ps.setTimestamp(5, new Timestamp(gramPack.getCreationTime().getTime()));
	ps.setString(6, gramPack.getLocalResourceManager());
	ps.setBoolean(7, gramPack.getJobCredentialEndpointUsed());
	ps.setBoolean(8, gramPack.isFileStageInUsed());
	ps.setBoolean(9, gramPack.isFileStageOutUsed());
	ps.setBoolean(10, gramPack.isFileCleanUpUsed());
	ps.setBoolean(11, gramPack.isCleanUpHoldUsed());
	ps.setByte(12, gramPack.getJobType());
	ps.setInt(13, gramPack.getGt2ErrorCode());
	ps.setByte(14, gramPack.getFaultClass());

	return ps;
    }
}
