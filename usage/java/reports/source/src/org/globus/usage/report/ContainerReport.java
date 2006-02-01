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
import java.io.PrintStream;

public class ContainerReport {

    // unique services for all containers
    private ServiceData allData = new ServiceData();

    // unqiue services per specific container
    private ServiceData servletData = new ServiceData();
    private ServiceData standaloneData = new ServiceData();
    private ServiceData otherData = new ServiceData();

    private static Map ipLookupTable = new HashMap();
    
    private static class ServiceData extends IPTable {

        private int containers;
        private int services;
        private Map uniqueServices = new HashMap();
        
        public void addService(String serviceName) {
            if (this.uniqueServices.get(serviceName) == null) {
                this.uniqueServices.put(serviceName, "");
            }
            this.services++;
        }

        public void addContainer() {
            this.containers++;
        }

        public void output(PrintStream out, String tab) {
            out.println(tab + "<containers>" + this.containers + "</containers>");
            out.println(tab + "<services>" + this.services + "</services>");
            out.println(tab + "<unique-services>" + this.uniqueServices.size() + "</unique-services>");
            super.output(out, tab);
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

            this.allData.addService(serviceName);

            switch (containerType) {
            case 1: 
                this.standaloneData.addService(serviceName);
                break;
            case 2: 
                this.servletData.addService(serviceName);
                break;
            default: 
                this.otherData.addService(serviceName);
                break;
            }
        }

        // over all data
        this.allData.addContainer();
        if (!isPrivateAddress) {
            this.allData.addAddress(ip);
        }
        

        // per container data
        ServiceData containerData = null;

        switch (containerType) {
        case 1: 
            containerData = this.standaloneData;
            break;
        case 2: 
            containerData = this.servletData;
            break;
        default: 
            containerData = this.otherData;
            break;
        }
        
        containerData.addContainer();
        if (!isPrivateAddress) {
            containerData.addAddress(ip);
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

                System.out.println("  <entry>");
                System.out.println("\t<start-date>" + startDateStr + "</start-date>");
                System.out.println("\t<end-date>" + endDateStr + "</end-date>");

                r.allData.discoverDomains(ipLookupTable);
                System.out.println("\t<all>");
                r.allData.output(System.out, "\t\t");
                System.out.println("\t</all>");

                r.standaloneData.discoverDomains(ipLookupTable);
                System.out.println("\t<standalone>");
                r.standaloneData.output(System.out, "\t\t");
                System.out.println("\t</standalone>");

                r.servletData.discoverDomains(ipLookupTable);
                System.out.println("\t<servlet>");
                r.servletData.output(System.out, "\t\t");
                System.out.println("\t</servlet>");

                r.otherData.discoverDomains(ipLookupTable);
                System.out.println("\t<other>");
                r.otherData.output(System.out, "\t\t");
                System.out.println("\t</other>");

                System.out.println("  </entry>");
            }
            
            System.out.println("</container-report>");

        } finally {
            if (con != null) {
                con.close();
            }
        }
    }
        
}

