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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.io.PrintStream;
import java.sql.Timestamp;

public class ContainerUpReport {

    private int period = 5; // always in secs
    private int steps = 20;

    private Map containers = new HashMap();
    private int[] slots = new int[steps+1];

    public void display() {

        int start = 0;
        int end = this.period;

        for (int i = 0; i< this.slots.length; i++) {
            System.out.println( i + " " + start + " " + end + ": " + this.slots[i]);
            start = end;
            end = end * 2;
        }
    }

    public void compute(int eventType,
                        Timestamp timestamp,
                        String containerID) {
        if (eventType == 1) {
            this.containers.put(containerID, timestamp);
        } else if (eventType == 2) {
            Timestamp startTime = (Timestamp)this.containers.remove(containerID);
            if (startTime != null) {
                long diff = timestamp.getTime() - startTime.getTime();

                int slot = getSlot(diff / 1000);
                slots[slot]++;
            }
        }
    }

    public int getSlot(long seconds) {
        int time = this.period;
        int i = 0;
        for (i = 0; i < this.steps; i++) {
            if (seconds < time) {
                return i;
            } else {
                time = time * 2;
            }
        }
        return i;
    }

    public static void main(String[] args) throws Exception {
    
        String driverClass = "org.postgresql.Driver";
        String url = "jdbc:postgresql://pgsql.mcs.anl.gov:5432/usagestats?user=allcock&password=bigio";
        String baseQuery = "select event_type,send_time,ip_address,container_id from java_ws_core_packets where ";

        Connection con = null;

        String inputDate = args[0];
        int n = Integer.parseInt(args[1]);
        String containerType = "all";
        if (args.length > 2) {
            containerType = args[2];
            baseQuery += " container_type = " + containerType + " and ";
        }

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

        ContainerUpReport r = new ContainerUpReport();

        try {
            Class.forName(driverClass);

            con = DriverManager.getConnection(url);

            Date date = dateFormat.parse(inputDate);

            Calendar calendar = dateFormat.getCalendar();

            if (n < 0) {
                calendar.add(Calendar.DATE, n);
                n = -n;
            }

            /*
            System.out.println("<container-uptime-report type=\"" + 
                               containerType + "\">");
            */

            Date startDate = calendar.getTime();
            calendar.add(Calendar.DATE, n);
            Date endDate = calendar.getTime();
            
            String startDateStr = dateFormat.format(startDate);
            String endDateStr = dateFormat.format(endDate);
            String timeFilter = "send_time >= '" + startDateStr + 
                "' and send_time < '" + endDateStr + "'";
                
            String query = baseQuery + timeFilter + " order by send_time";

            System.out.println(query);

            Statement stmt = con.createStatement();

            ResultSet rs = stmt.executeQuery(query);
                
            while (rs.next()) {
                r.compute(rs.getInt(1), rs.getTimestamp(2), rs.getString(4) + rs.getString(3));
            }
            
            rs.close();
            stmt.close();

        } finally {
            if (con != null) {
                con.close();
            }
        }

        r.display();
    }
        
}

