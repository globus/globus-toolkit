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
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.io.PrintStream;
import java.sql.Timestamp;

public class ContainerLongUpReport extends BaseContainerUpReport {

    private Map containers = new HashMap();
    private Map uptimes = new HashMap();

    public ContainerLongUpReport() {
        initializeSlots();
    }

    public void output(PrintStream out) {
        Iterator iter = this.uptimes.entrySet().iterator();
        while(iter.hasNext()) {
            Map.Entry entry = (Map.Entry)iter.next();
            Long time = (Long)entry.getValue();

            Slot s = getSlot(time.longValue()/1000);
            s.increment();
        }

        super.output(out);
    }

    public void compute(int eventType,
                        Timestamp timestamp,
                        String containerID,
                        String ip) {
        if (eventType == 1) { // start
            this.containers.put(containerID, timestamp);
        } else if (eventType == 2) { // stop
            Timestamp startTime = 
                (Timestamp)this.containers.remove(containerID);
            if (startTime != null) {
                long diff = timestamp.getTime() - startTime.getTime();
                updateUptime(ip, diff);
            }
        }
    }

    private void updateUptime(String ip, long msec) {
        Long time = (Long)this.uptimes.get(ip);
        if (time == null || time.longValue() < msec) {
            this.uptimes.put(ip, new Long(msec));
        }
    }
    
    public static void main(String[] args) throws Exception {
    
        String baseQuery = "select event_type,send_time,ip_address,container_id from java_ws_core_packets where ";

        Connection con = null;

        if (args.length == 0) {
            System.err.println("Usage: java ContainerLongUpReport [options] <date (yyyy-MM-dd)>");
            System.exit(1);
        }

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

        ContainerLongUpReport r = new ContainerLongUpReport();

        try {
            Database db = new Database();

            con = DriverManager.getConnection(db.getURL());

            Date date = dateFormat.parse(inputDate);

            Calendar calendar = dateFormat.getCalendar();

            if (n < 0) {
                calendar.add(step, n);
                n = -n;
            }

            Date startDate = calendar.getTime();
            calendar.add(step, n);
            Date endDate = calendar.getTime();
            
            String startDateStr = dateFormat.format(startDate);
            String endDateStr = dateFormat.format(endDate);
            String timeFilter = "send_time >= '" + startDateStr + 
                "' and send_time < '" + endDateStr + "'";
                
            String query = baseQuery + timeFilter + " order by send_time";

            System.out.println("<container-long-uptime-report container_type=\"" + 
                               containerType + "\">");
            System.out.println("  <start-date>" + startDateStr + "</start-date>");
            System.out.println("  <end-date>" + endDateStr + "</end-date>");

            Statement stmt = con.createStatement();

            ResultSet rs = stmt.executeQuery(query);
                
            while (rs.next()) {
                String ip = rs.getString(3);
                r.compute(rs.getInt(1), rs.getTimestamp(2), 
                          rs.getString(4) + ip,
                          ip);
            }
            
            rs.close();
            stmt.close();

            r.output(System.out);

            System.out.println("</container-long-uptime-report>");

        } finally {
            if (con != null) {
                con.close();
            }
        }
    }
        
}

