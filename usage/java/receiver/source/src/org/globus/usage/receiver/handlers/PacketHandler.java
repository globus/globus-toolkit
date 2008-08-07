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

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;

import java.util.Properties;

public interface PacketHandler {
    /* Indicate willingness to handle the packet */
    public boolean doCodesMatch(short componentCode, short versionCode);
    /* Allocate the appropriate packet type for the handler to consume */
    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes);
    /* Handle packet */
    public void handlePacket(UsageMonitorPacket pack);
    /* Clear count of handled/dropped packets */
    public void resetCounts();
    /* Get status string related to handler-specific processing */
    public String getStatus();

    public void shutDown();
}
