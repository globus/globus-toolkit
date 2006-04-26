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
    
        String USAGE = "Usage: java ContainerReport [options] <date (yyyy-MM-dd)>";
        String HELP = 
            "Where [options] are:\n" +
            "  -help                    Displays this message\n" +
            "  -step <day|month>        Specifies step type (default: 'day')\n" +
            "  -n <steps>               Specifies number of steps to do to\n" +
            "                           determine end date (default: 1)\n" +
            "\n";
        
        if (args.length == 0) {
            System.err.println(USAGE);
            System.exit(1);
        } else if (args.length == 1 && args[0].equalsIgnoreCase("-help")) {
            System.err.println(USAGE);
            System.err.println(HELP);
            System.exit(1);
        }

        String baseQuery = "select service_list,container_type,ip_address from java_ws_core_packets where event_type = 1 and ";
        int n = 1;
        String containerType = "all";
        String stepStr = "day";

        for (int i=0;i<args.length-1;i++) {
            if (args[i].equals("-n")) {
                n = Integer.parseInt(args[++i]);
            } else if (args[i].equals("-type")) {
                baseQuery += " container_type = " + args[++i] + " and ";
            } else if (args[i].equals("-step")) {
                stepStr = args[++i];
            } else if (args[i].equalsIgnoreCase("-help")) {
                System.err.println(USAGE);
                System.err.println(HELP);
                System.exit(1);
            } else {
                System.err.println("Unknown argument: " + args[i]);
                System.exit(1);
            }
        }

        String inputDate = args[args.length-1];

        // parse step info
        int step = -1;
        if (stepStr.equalsIgnoreCase("day")) {
            step = Calendar.DATE;
        } else if (stepStr.equalsIgnoreCase("month")) {
            step = Calendar.MONTH;
        } else {
            System.err.println("Unsupported step: " + stepStr);
            System.exit(2);
        }

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

        Connection con = null;

        try {
            Database db = new Database();

            con = DriverManager.getConnection(db.getURL());

            Date date = dateFormat.parse(inputDate);

            Calendar calendar = dateFormat.getCalendar();

            if (n < 0) {
                calendar.add(step, n);
                n = -n;
            }

            System.out.println("<container-report type=\"" + 
                               containerType + "\">");

            for (int i=0;i<n;i++) {
                Date startDate = calendar.getTime();
                calendar.add(step, 1);
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

