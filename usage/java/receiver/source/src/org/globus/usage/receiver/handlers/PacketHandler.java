/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

package org.globus.usage.receiver.handlers;

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;

public interface PacketHandler {
    /*I separate instantiating and handling the packet to make it easier
      to reuse code -- in case, for instance, you want to write two handlers
      which instantiate the same packet subclass, but do two different
      things to the resulting packet... or vice-versa.*/

    public boolean doCodesMatch(short componentCode, short versionCode);
    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes);
    public void handlePacket(UsageMonitorPacket pack);
}
