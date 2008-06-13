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
package org.globus.usage.report.common;

import java.net.InetAddress;

public class IPEntry {

    public static final IPEntry NULL_IP = new IPEntry("unresolved");

    String domain;

    public IPEntry(String domain) {
        this.domain = domain;
    }

    public String getDomain() {
        return domain;
    }

    public static IPEntry getIPEntry(String ip) {
        return getIPEntry(ip, true);
    }
    
    public static IPEntry getIPEntry(String ip, boolean groupCommon) {
        String hostname = null;
        int slashOff = ip.indexOf('/');

        if (slashOff != -1 ) {
            hostname = ip.substring(0, slashOff);
            ip = ip.substring(slashOff+1);
        }

        try {
            InetAddress ia = InetAddress.getByName(ip);

            if (groupCommon) {
                byte [] addressBytes = ia.getAddress();

                if (IPTable.isPrivateAddress(ia)) {
                    return new IPEntry("Private");
                } else if (addressBytes.length == 4) {
                    if (addressBytes[0] == (byte) 128 &&
                        addressBytes[1] == (byte) 9) {
                        return new IPEntry("ISI");
                    } else if (addressBytes[0] == (byte) 140 &&
                               addressBytes[1] == (byte) 221) {
                        return new IPEntry("MCS");
                    }
                }
            } else if (IPTable.isPrivateAddress(ia)) {
                return IPEntry.NULL_IP;
            }

            if (hostname == null || hostname.equals("")) {
                hostname = ia.getHostName();
            }
        } catch (Exception e) {
            return IPEntry.NULL_IP;
        }


        int pos = hostname.lastIndexOf('.');
        if (pos != -1) {
            String domain = hostname.substring(pos + 1);
            if (! Character.isDigit(domain.charAt(0))) {
                return new IPEntry(domain.toLowerCase());
            }
        }
        return IPEntry.NULL_IP;
    }
}
