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

public class ContainerUpReport {

    private static final long SEC_PER_HOUR = 60 * 60;
    private static final long SEC_PER_DAY =  SEC_PER_HOUR * 24;
    private static final long SEC_PER_MONTH =  SEC_PER_DAY * 30;
    private static final long SEC_PER_YEAR =  SEC_PER_MONTH * 12;

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
            this.slots.add(new Slot(SEC_PER_HOUR * i * 3));
        }
        // days
        for (int i=1;i<=10;i++) {
            this.slots.add(new Slot(SEC_PER_DAY * i * 3));
        }
        // months
        for (int i=1;i<=6;i++) {
            this.slots.add(new Slot(SEC_PER_MONTH * i * 2));
        }
    }

    public void output(PrintStream out) {
        for (int i = 0; i< this.slots.size(); i++) {
            Slot slot = (Slot)this.slots.get(i);
            out.println("  <slot>");
            out.println("   <time>" + slot.getTime() + "</time>");
            out.println("   <timeStr>" + formatTimeSec(slot.getTime()) + "</timeStr>");
            out.println("   <count>" + slot.getCount() + "</count>");
            out.println("  </slot>");
        }
    }
    
    // time in sec
    public static String formatTimeSec(long time) {
        
        if (time < 60) {
            return ((time == 1) ? "1 second" : time + " seconds");
	} 

        StringBuffer str = new StringBuffer();

        long years = time / SEC_PER_YEAR;
        if (years > 0) {
            str.append((years == 1) ? "1 year" : years + " years");
            time -= years * SEC_PER_YEAR;
        }

        long months = time / SEC_PER_MONTH; // assumes 30 days per month
        if (months > 0) {
            if (str.length() != 0) str.append(", ");
            str.append((months == 1) ? "1 month" : months + " months");
            time -= months * SEC_PER_MONTH;
        }
    
	long days = time / SEC_PER_DAY;
    
	if (days > 0) {
            if (str.length() != 0) str.append(", ");
	    str.append((days == 1) ? "1 day" :  days + " days");
	    time -= days *  SEC_PER_DAY;
	}
    
	long hours = time / SEC_PER_HOUR;
    
	if (hours > 0) {
	    if (str.length() != 0) str.append(", ");
	    str.append((hours == 1) ? "1 hour" : hours + " hours");
	    time -= hours * SEC_PER_HOUR;
	}
        
	long mins = time / 60;
        
	if (mins > 0) {
	    if (str.length() != 0) str.append(", ");
	    str.append((mins == 1) ? "1 minute" : mins + " minutes");
	    time -= mins * 60;
	}
    
	long sec = time;
    
	if (sec > 0) {
	    if (str.length() != 0) str.append(", ");
	    str.append((sec == 1) ? "1 second" : sec + " seconds");
	}
    
	return str.toString();
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

            Date startDate = calendar.getTime();
            calendar.add(step, n);
            Date endDate = calendar.getTime();
            
            String startDateStr = dateFormat.format(startDate);
            String endDateStr = dateFormat.format(endDate);
            String timeFilter = "send_time >= '" + startDateStr + 
                "' and send_time < '" + endDateStr + "'";
                
            String query = baseQuery + timeFilter + " order by send_time";

            System.out.println("<container-uptime-report container_type=\"" + 
                               containerType + "\">");
            System.out.println("  <start-date>" + startDateStr + "</start-date>");
            System.out.println("  <end-date>" + endDateStr + "</end-date>");

            Statement stmt = con.createStatement();

            ResultSet rs = stmt.executeQuery(query);
                
            while (rs.next()) {
                r.compute(rs.getInt(1), rs.getTimestamp(2), rs.getString(4) + rs.getString(3));
            }
            
            rs.close();
            stmt.close();

            r.output(System.out);

            System.out.println("</container-uptime-report>");

        } finally {
            if (con != null) {
                con.close();
            }
        }
    }
        
}

