package org.globus.usage.receiver.handlers;

public interface PacketHandler {
    /*I separate instantiating and handling the packet to make it easier
      to reuse code -- in case, for instance, you want to write two handlers
      which instantiate the same packet subclass, but do two different
      things to the resulting packet... or vice-versa.*/

    public boolean doCodesMatch(short componentCode, short versionCode);
    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes);
    public void handlePacket(UsageMonitorPacket pack);
}
