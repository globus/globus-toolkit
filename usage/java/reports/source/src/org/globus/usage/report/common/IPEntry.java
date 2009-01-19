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
        String hostname = "";
        int i = ip.indexOf("/");
        if (i != -1)
        {
            hostname = ip.substring(0,i);
            ip = ip.substring(i+1);
        }
        if (hostname.equals(""))
        {
            try {
                hostname = InetAddress.getByName(ip).getHostName();
            } catch (Exception e) {
                return IPEntry.NULL_IP;
            }
        }

        if (groupCommon) {
            if (ip.startsWith("128.9")) {
                return new IPEntry("ISI");
            } else if (ip.startsWith("140.221")) {
                return new IPEntry("MCS");
            } else if (IPTable.isPrivateAddress("/" + ip)) {
                return new IPEntry("Private");
            }
        }

        int pos = hostname.lastIndexOf('.');
        if (pos != -1) {
            String domain = hostname.substring(pos + 1);
            if (Character.isDigit(domain.charAt(0))) {
                // System.out.println("unable to get domain: "+ ip);
            } else {
                return new IPEntry(domain.toLowerCase());
            }
        }
        return IPEntry.NULL_IP;
    }
}
