package org.globus.usage.report;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

public class ServiceEntry {

    int standalone;
    int servlet;
    int other;
    
    HashMap uniqueIPs = new HashMap();
    HashMap domains = new HashMap();
    
    public void standalone() {
        standalone++;
    }

    public void servlet() {
        servlet++;
    }

    public void other() {
        other++;
    }

    public void addDomain(String domain) {
        DomainEntry c = (DomainEntry)domains.get(domain);
        if (c == null) {
            c = new DomainEntry(domain);
            domains.put(domain, c);
        }
        c.increment();
    }
    
    public void addAddress(String address) {
        uniqueIPs.put(address, "");
    }
    
    public int getStandaloneCount() {
        return standalone;
    }

    public int getServletCount() {
        return servlet;
    }

    public int getOtherCount() {
        return other;
    }

    public int getUniqueIPCount() {
        return this.uniqueIPs.size();
    }

    public Map getUniqueIPList() {
        return this.uniqueIPs;
    }

    public Map getDomains() {
        return this.domains;
    }

    public List getSortedDomains() {
        List input = new ArrayList(this.domains.values());
        Collections.sort(input, new DomainEntry(null));
        return input;
    }

    // FIXME: does not handle ipv6 address
    public static boolean isPrivateAddress(String address) {
        // TODO: could use InetAddress instead?!
        if (address.startsWith("/127.") ||
            address.startsWith("/10.") ||
            address.startsWith("/192.168.")) {
            return true;
        } else if (address.startsWith("/172.")) {
            int start = "/172.".length();
            int pos = address.indexOf('.', start+1);
            if (pos != -1) {
                String octet = address.substring(start, pos);
                int octetValue = Integer.parseInt(octet);
                if (octetValue >= 16 || octetValue <= 31) {
                    return true;
                }
            }
            return false;
        } else {
            return false;
        }
    }

    public static class DomainEntry implements Comparator {
        String domain;
        int value;
        
        public DomainEntry(String domain) {
            this.domain = domain;
            this.value = value;
        }

        public void increment() {
            this.value++;
        }
        
        public String getDomain() {
            return this.domain;
        }

        public int getCount() {
            return this.value;
        }

        public int compare(Object o1, Object o2) {
            int thisVal = ((DomainEntry)o2).value;
            int anotherVal = ((DomainEntry)o1).value;
            return (thisVal<anotherVal ? -1 : (thisVal==anotherVal ? 0 : 1));
        }

        public String toString() {
            return domain + " " + value;
        }
    }
}
