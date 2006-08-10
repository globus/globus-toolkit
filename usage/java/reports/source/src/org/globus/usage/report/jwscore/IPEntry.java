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
package org.globus.usage.report.jwscore;

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
        String hostname = null;
        try {
            hostname = InetAddress.getByName(ip).getHostName();
        } catch (Exception e) {
            return IPEntry.NULL_IP;
        }

        int pos = hostname.lastIndexOf('.');
        if (pos != -1) {
            String domain = hostname.substring(pos+1);
            if (Character.isDigit(domain.charAt(0))) {
                //System.out.println("unable to get domain: "+ ip);
            } else {
                return new IPEntry(domain.toLowerCase());
            }
        }
        
        return IPEntry.NULL_IP;
    }
}
