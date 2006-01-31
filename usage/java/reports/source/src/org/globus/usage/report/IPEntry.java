package org.globus.usage.report;

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
