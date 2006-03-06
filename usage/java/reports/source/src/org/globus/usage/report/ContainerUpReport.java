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

import org.globus.util.Util;

public class ContainerUpReport {

    private Map containers = new HashMap();
    private List slots = new ArrayList();

    public ContainerUpReport() {

        this.slots.add(new Slot(0));

        // 2 mins
        this.slots.add(new Slot(60 * 2));

        // 5 mins
        this.slots.add(new Slot(60 * 5));

        // minutes
        for (int i=1;i<=6;i++) {
            this.slots.add(new Slot(60 * i * 10));
        }
        // hours
        for (int i=1;i<=8;i++) {
            this.slots.add(new Slot(3600 * i * 3));
        }
        // days
        for (int i=1;i<=10;i++) {
            this.slots.add(new Slot(3600 * 24 * i * 3));
        }
        // months
        for (int i=1;i<=6;i++) {
            this.slots.add(new Slot(3600 * 24 * 30 * i * 2));
        }
    }

    public void display() {
        for (int i = 0; i< this.slots.size(); i++) {
            Slot slot = (Slot)this.slots.get(i);
            System.out.println(Util.formatTimeSec(slot.getTime()) + 
                               ": " + slot.getCount());
        }
    }
    
    private static class Slot {
        private int count;
        private long time;
        
        public Slot(long time) {
            this.time = time;
        }
        public void increment() {
            this.count++;
        }
        public int getCount() {
            return this.count;
        }
        public long getTime() {
            return this.time;
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

                Slot slot = getSlot(diff / 1000);
                slot.increment();
            }
        }
    }

    public Slot getSlot(long seconds) {
        for (int i = 0; i < this.slots.size(); i++) {
            Slot slot = (Slot)this.slots.get(i);
            if (seconds < slot.getTime()) {
                return slot;
            }
        }
        return (Slot)this.slots.get(this.slots.size()-1);
    }
    
    public static void main(String[] args) throws Exception {
    
        String baseQuery = "select event_type,send_time,ip_address,container_id from java_ws_core_packets where ";

        Connection con = null;

        if (args.length == 0) {
            System.err.println("Usage: java ContainerUpReport [options] <date (yyyy-MM-dd)>");
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

        ContainerUpReport r = new ContainerUpReport();

        try {
            Database db = new Database();

            con = DriverManager.getConnection(db.getURL());

            Date date = dateFormat.parse(inputDate);

            Calendar calendar = dateFormat.getCalendar();

            if (n < 0) {
                calendar.add(step, n);
                n = -n;
            }

            /*
            System.out.println("<container-uptime-report type=\"" + 
                               containerType + "\">");
            */

            Date startDate = calendar.getTime();
            calendar.add(step, n);
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

