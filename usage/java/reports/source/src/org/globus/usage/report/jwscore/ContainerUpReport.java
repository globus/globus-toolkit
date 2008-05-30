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

import java.sql.ResultSet;

import java.util.HashMap;
import java.util.Map;
import java.util.Date;
import java.util.Calendar;
import java.text.SimpleDateFormat;
import java.sql.Timestamp;

import org.globus.usage.report.common.DatabaseRetriever;

public class ContainerUpReport extends BaseContainerUpReport {

    private Map containers = new HashMap();

    public ContainerUpReport() {
        initializeSlots();
    }

    public void compute(int eventType,
                        Timestamp timestamp,
                        String containerID) {
        if (eventType == 1) {
            this.containers.put(containerID, timestamp);
        } else if (eventType == 2) {
            Timestamp startTime = 
                (Timestamp)this.containers.remove(containerID);
            if (startTime != null) {
                long diff = timestamp.getTime() - startTime.getTime();
                if (diff < 0) {
                    return;
                }
                Slot slot = getSlot(diff / 1000);
                slot.increment();
            }
        }
    }
    
    public static void main(String[] args) throws Exception {
        
        String USAGE = "Usage: java ContainerUpReport [options] <date (yyyy-MM-dd)>";
        String HELP = 
            "Where [options] are:\n" +
            "  -help                    Displays this message\n" +
            "  -step <day|month>        Specifies step type (default: 'day')\n" +
            "  -n <steps>               Specifies number of steps to do to\n" +
            "                           determine end date (default: 1)\n" +
            "  -table TABLENAME         Use TABLENAME instead of the\n" +
            "                           java_ws_core_packets table\n" +
            "\n";
        
        if (args.length == 0) {
            System.err.println(USAGE);
            System.exit(1);
        } else if (args.length == 1 && args[0].equalsIgnoreCase("-help")) {
            System.err.println(USAGE);
            System.err.println(HELP);
            System.exit(1);
        }
        
        String baseQueryStart = "select event_type,send_time,ip_address,container_id,version_code from ";
        String table = "java_ws_core_packets";
        String baseQueryEnd = " where ";
        int n = 1;
        String containerType = "all";
        String stepStr = "day";
        
        for (int i=0;i<args.length-1;i++) {
            if (args[i].equals("-n")) {
                n = Integer.parseInt(args[++i]);
            } else if (args[i].equals("-type")) {
                baseQueryEnd += " container_type = " + args[++i] + " and ";
            } else if (args[i].equals("-step")) {
                stepStr = args[++i];
            } else if (args[i].equalsIgnoreCase("-help")) {
                System.err.println(USAGE);
                System.err.println(HELP);
                System.exit(1);
            } else if (args[i].equals("-table")) {
                table = args[++i];
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

        ContainerUpReport r = new ContainerUpReport();

        DatabaseRetriever db = null;

        try {
            db = new DatabaseRetriever();

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
            String timeFilter = "DATE(send_time) >= '" + startDateStr + 
                "' and DATE(send_time) < '" + endDateStr + "'";
                
            String query = baseQueryStart + table + baseQueryEnd + timeFilter
                         + " order by send_time";

            System.out.println("<container-uptime-report container_type=\"" + 
                               containerType + "\">");
            System.out.println("  <start-date>" + startDateStr + "</start-date>");
            System.out.println("  <end-date>" + endDateStr + "</end-date>");

            ResultSet rs = db.retrieve(query);
                
            while (rs.next()) {
                String ip = rs.getString(3);
                String containerId = rs.getString(4);
                String packetVersion = rs.getString(5);

                r.compute(rs.getInt(1), rs.getTimestamp(2),
                          ip + "/" + containerId + "/" + packetVersion);
            }
            
            rs.close();

            r.output(System.out);

            System.out.println("</container-uptime-report>");

        } finally {
            if (db != null) {
                db.close();
            }
        }
    }
        
}

