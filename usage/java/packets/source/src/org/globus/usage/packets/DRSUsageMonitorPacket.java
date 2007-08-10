/*
 * Copyright 1999-2007 University of Chicago
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

package org.globus.usage.packets;

import java.net.Inet6Address;
import java.sql.Timestamp;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Connection;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/*DRS usage monitor packets, in addition to the fields in IPTimeMonitorPacket,
include the following:
    - current number of DRS resources in the system
    - number of file replications in this request
*/
public class DRSUsageMonitorPacket extends IPTimeMonitorPacket {
    static Log log = LogFactory.getLog(DRSUsageMonitorPacket.class);

    public static final short COMPONENT_CODE = 9;
    public static final short PACKET_VERSION = 0;

    private long numberOfFiles;
    private long numberOfResources;

    public DRSUsageMonitorPacket() {
        super();
        this.componentCode = COMPONENT_CODE;
        this.packetVersion = PACKET_VERSION;
    }

    public long getNumberOfFiles() {
        return this.numberOfFiles;
    }
    public void setNumberOfFiles(long numberOfFiles) {
        this.numberOfFiles = numberOfFiles;
    }
    public long getNumberOfResources() {
        return this.numberOfResources;
    }
    public void setNumberOfResources(long numberOfResources) {
        this.numberOfResources = numberOfResources;
    }
    public void packCustomFields(CustomByteBuffer buf) {
        super.packCustomFields(buf);
        buf.putLong(this.numberOfFiles);
        buf.putLong(this.numberOfResources);
    }

    public void unpackCustomFields(CustomByteBuffer buf) {
        super.unpackCustomFields(buf);
        this.numberOfFiles = buf.getLong();
        this.numberOfResources = buf.getLong();
    }

    public void display() {
        log.info(super.toString());
        log.info("Number of Files : " + this.numberOfFiles);
        log.info("Number of Resources : " + this.numberOfResources);
    }
}
