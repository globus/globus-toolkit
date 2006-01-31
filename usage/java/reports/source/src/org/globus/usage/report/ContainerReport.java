package org.globus.usage.report;

import java.sql.DriverManager;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;

import java.util.HashMap;
import java.util.TreeMap;
import java.util.Comparator;
import java.util.Map;
import java.util.Iterator;
import java.util.StringTokenizer;
import java.util.Date;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.net.InetAddress;
import java.text.SimpleDateFormat;

public class ContainerReport {

    // unique services for all containers
    private Map totalServices = new HashMap();

    // unqiue services per specific container
    private Map servletServices = new HashMap();
    private Map standaloneServices = new HashMap();
    private Map otherServices = new HashMap();

    private ServiceEntry containerEntry = new ServiceEntry();

    private static Map ipLookupTable = new HashMap();
    
    public void discoverDomains() {
        Iterator ipIter = 
            containerEntry.getUniqueIPList().keySet().iterator();
        while(ipIter.hasNext()) {
            String ip = (String)ipIter.next();
            
            IPEntry ipEntry = (IPEntry)ipLookupTable.get(ip);
            if (ipEntry == null) {
                ipEntry = IPEntry.getIPEntry(ip);
                ipLookupTable.put(ip, ipEntry);
            }
            
            containerEntry.addDomain(ipEntry.getDomain());
        }
    }
    
    public void compute(String listOfServices,
                        int containerType,
                        String ip) {
        // handle the case where all the service names do not fit in the
        // packet
        if (listOfServices.length() >= 1445) {
            int pos = listOfServices.lastIndexOf(',');
            if (pos != -1) {
                listOfServices = listOfServices.substring(0, pos);
            }
        } 

        boolean isPrivateAddress = ServiceEntry.isPrivateAddress(ip);
        if (ip.startsWith("/")) {
            ip = ip.substring(1);
        }
        
        StringTokenizer tokens = new StringTokenizer(listOfServices, ",");
        while(tokens.hasMoreTokens()) {
            String serviceName = tokens.nextToken();
            
            if (totalServices.get(serviceName) == null) {
                totalServices.put(serviceName, "");
            }

            switch (containerType) {
            case 1: 
                if (standaloneServices.get(serviceName) == null) {
                    standaloneServices.put(serviceName, "");
                }
                break;
            case 2: 
                if (servletServices.get(serviceName) == null) {
                    servletServices.put(serviceName, "");
                }
                break;
            default: 
                if (otherServices.get(serviceName) == null) {
                    otherServices.put(serviceName, "");
                }
                break;
            }
        }

        switch (containerType) {
        case 1: 
            containerEntry.standalone(); break;
        case 2: 
            containerEntry.servlet(); break;
        default: 
            containerEntry.other(); break;
        }
        
        if (!isPrivateAddress) {
            containerEntry.addAddress(ip);
        }
    }

    public static void main(String[] args) throws Exception {
    
        String driverClass = "org.postgresql.Driver";
        String url = "jdbc:postgresql://pgsql.mcs.anl.gov:5432/usagestats?user=allcock&password=bigio";
        String baseQuery = "select service_list,container_type,ip_address from java_ws_core_packets where event_type = 1 and ";

        Connection con = null;

        String inputDate = args[0];
        int n = Integer.parseInt(args[1]);
        String containerType = "all";
        if (args.length > 2) {
            containerType = args[2];
            baseQuery += " container_type = " + containerType + " and ";
        }

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

        try {
            Class.forName(driverClass);

            con = DriverManager.getConnection(url);

            Date date = dateFormat.parse(inputDate);

            Calendar calendar = dateFormat.getCalendar();

            if (n < 0) {
                calendar.add(Calendar.DATE, n);
                n = -n;
            }

            System.out.println("<container-report type=\"" + 
                               containerType + "\">");

            for (int i=0;i<n;i++) {
                Date startDate = calendar.getTime();
                calendar.add(Calendar.DATE, 1);
                Date endDate = calendar.getTime();

                String startDateStr = dateFormat.format(startDate);
                String endDateStr = dateFormat.format(endDate);
                String timeFilter = "send_time >= '" + startDateStr + 
                    "' and send_time < '" + endDateStr + "'";
                
                String query = baseQuery + timeFilter;

                Statement stmt = con.createStatement();

                ResultSet rs = stmt.executeQuery(query);
                
                ContainerReport r = new ContainerReport();

                while (rs.next()) {
                    r.compute(rs.getString(1), rs.getInt(2), rs.getString(3));
                }

                rs.close();
                stmt.close();

                r.discoverDomains();

                System.out.println("  <entry>");
                System.out.println("\t<start-date>" + startDateStr + "</start-date>");
                System.out.println("\t<end-date>" + endDateStr + "</end-date>");
                System.out.println("\t<services-all>" + r.totalServices.size() + "</services-all>");
                System.out.println("\t<services-standalone>" + r.standaloneServices.size() + "</services-standalone>");
                System.out.println("\t<services-servlet>" + r.servletServices.size() + "</services-servlet>");
                System.out.println("\t<services-other>" + r.otherServices.size() + "</services-other>");
                System.out.println("\t<unique-ip>" + r.containerEntry.getUniqueIPCount() + "</unique-ip>");
                System.out.println("\t<domains>");
                Iterator iter = r.containerEntry.getSortedDomains().iterator();
                while(iter.hasNext()) {
                    ServiceEntry.DomainEntry entry = 
                        (ServiceEntry.DomainEntry)iter.next();
                    System.out.println("\t\t<domain-entry name=\"" + 
                                       entry.getDomain() + "\" count=\"" +
                                       entry.getCount() + "\"/>");
                }
                System.out.println("\t</domains>");
                System.out.println("  </entry>");

                
                /**
                           containerEntry.getStandaloneCount() + ", " +
                           containerEntry.getServletCount() + ", " +

                **/

            }
            
            System.out.println("</container-report>");

        } finally {
            if (con != null) {
                con.close();
            }
        }
    }
        
}

