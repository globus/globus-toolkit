/*
 * Copyright 1999-2008 University of Chicago
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
package org.globus.usage.report.combined;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.sql.ResultSet;

import org.globus.usage.report.common.DatabaseRetriever;

public class UsageDiff {
    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java UsageDiff [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

        String HELP = "Where [options] are:\n"
                + " -help                 Displays help\n"
                + " -step <day|month>     Size of step [default: day]\n"
                + " -n <steps>            Number of steps [defalt: 1]\n"
                + " -t <table>            Database table to process [default: gram_packets]\n" 
                + " -c <host-column>      Database column containing unique host identifier [default: ip_address]\n"
                + " -r <report-name>      Name of the report [default: combined-gramusagediff-report]";

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

        int n = 1;
        int i = 0;
        int step = Calendar.DATE;
        String table = "gram_packets";
        String hostColumn = "ip_address";
        String reportName = "combined-gramusagediff-report";
        Date date = null;

        try {
            for (i = 0; i < args.length; i++) {
                if (args[i].equals("-help") || args[i].equals("-h")) {
                    System.err.println(USAGE);
                    System.err.println(HELP);
                    System.exit(0);
                } else if (args[i].equals("-step")) {
                    String stepStr = args[++i];
                    if (stepStr.equalsIgnoreCase("day")) {
                        step = Calendar.DATE;
                    } else if (stepStr.equalsIgnoreCase("month")) {
                        step = Calendar.MONTH;
                    } else {
                        System.err.println("Unsupported step: " + stepStr);
                        System.err.println(USAGE);
                        System.exit(0);
                    }
                } else if (args[i].equals("-n")) {
                    n = Integer.parseInt(args[++i]);
                } else if (args[i].equals("-t")) {
                    table = args[++i];
                } else if (args[i].equals("-c")) {
                    hostColumn = args[++i];
                } else if (args[i].equals("-r")) {
                    reportName = args[++i];
                } else if (i == (args.length -1)) {
                    date = dateFormat.parse(args[i]);
                } else {
                    System.err.println("Unknown argument: " + args[i]);
                    System.out.println(USAGE);
                    System.exit(1);
                }
            }
        } catch (Exception e) {
            System.err.println("Error parsing argument " + args[i]);
            System.out.println(USAGE);
            System.exit(1);
        }

        if (date == null) {
            System.err.println("Missing parameter <date>");
            System.out.println(USAGE);
            System.exit(1);
        }

        DatabaseRetriever dbr = new DatabaseRetriever();

        Calendar calendar = dateFormat.getCalendar();
        if (n < 0) {
            calendar.add(step, n);
            n = -n;
        }
        Date sDate = calendar.getTime();
        calendar.add(step, n);
        Date endDate = calendar.getTime();

        String startDateStr = dateFormat.format(sDate);
        String endDateStr = dateFormat.format(endDate);

        String query = "SELECT summary.weeks, COUNT(*) " +
                       "FROM( " +
                       "    SELECT " +
                       "        " + hostColumn + ", "+
                       "        TRUNC( "+
                       "            DATE_PART('days', " +
                       "            MAX(send_time) - MIN(send_time)) / 7) " +
                       "        AS weeks " +
                       "    FROM " + table + " " +
                       "    WHERE " +
                       "        DATE(send_time) >= '" + startDateStr + "' " +
                       "    AND " +
                       "        DATE(send_time) < '" + endDateStr + "' " +
                       "    GROUP BY " + hostColumn + ") " +
                       "AS summary " +
                       "GROUP BY " +
                       "    summary.weeks ORDER BY summary.weeks;";

        System.err.println(query);
        System.out.println("<" + reportName + ">");
        System.out.println("  <start-date>" + startDateStr + "</start-date>");
        System.out.println("  <end-date>" + endDateStr + "</end-date>");

        ResultSet rs = null;

        rs = dbr.retrieve(query);

        while (rs.next())
        {
            int weeks = rs.getInt(1);
            long count = rs.getLong(2);
            int weeks_in_secs = weeks * 7 * 24 * 60 * 60;
            String unit = (weeks == 1) ? " week" : " weeks";

            System.out.println("  <slot>");
            System.out.println("   <time>" + weeks_in_secs + "</time>");
            System.out.println("   <timeStr>" + weeks + unit + "</timeStr>");
            System.out.println("   <count>" + count + "</count>");
            System.out.println("  </slot>");
        }
        rs.close();
        dbr.close();

        System.out.println("</" + reportName + ">");

    }
}
