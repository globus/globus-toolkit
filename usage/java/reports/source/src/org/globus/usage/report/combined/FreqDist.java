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

import org.globus.usage.report.common.DatabaseRetriever;

import java.sql.ResultSet;

import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.Calendar;

import org.globus.usage.report.common.HistogramParser;
import org.globus.usage.report.common.TimeStep;

public class FreqDist {
    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: FreqDist [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

        String HELP = "Where [options] are:\n"
                + " -help                 Displays help\n"
                + " -step <day|month>     Specifies size of step (day by default)\n"
                + " -n <steps>            Specifies number of steps to do\n"
                + " -t <table>            Database table to process [default: gram_packets]\n" 
                + " -c <host-column>      Database column containing unique host identifier [default: ip_address]\n"
                + " -r <report-name>      Name of the report [default: combined-gramfreqdist-report]";
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

        int n = 1;
        int i = 0;
        int step = Calendar.DATE;
        String table = "gram_packets";
        String hostColumn = "ip_address";
        String reportName = "combined-gramfreqdist-report";
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
        TimeStep ts = new TimeStep(sDate, step, 1, n);
        HistogramParser histogram = new HistogramParser(
            "Service load (packets per day averaged across services reporting > 1 month)" , reportName,
            "count" ,ts);

        int slots[] = new int[] { 0, 1, 11, 101, 1001, 10001, 100001 };

        String query = "SELECT bin.min_rate, bin.max_rate, COUNT(*) "+
                       "FROM ("+
                       "    SELECT " +
                       "        summary.ip_address, " +
                       "        TRUNC(summary.count / summary.days) as ppd " +
                       "    FROM ("+
                       "        SELECT " +
                       "            " + hostColumn + ", " +
                       "            COUNT(*) as count, " +
                       "            DATE_PART('days', " +
                       "                MAX(send_time) - MIN(send_time)) " +
                       "                AS days "+
                       "        FROM " + table + " " +
                       "        WHERE "+
                       "            DATE(send_time) >= '" + startDateStr + "' "+
                       "        AND " +
                       "            DATE(send_time) < '" + endDateStr + "' "+
                       "        GROUP BY " + hostColumn + ") AS summary "+
                       "    WHERE summary.days >= 30) AS c "+
                       "INNER JOIN "+
                       "( "+
                       "    SELECT 0 AS min_rate, 0.99 AS max_rate "+
                       "    UNION ALL "+
                       "    SELECT 1 AS min_rate, 10 AS max_rate "+
                       "    UNION ALL "+
                       "    SELECT 11 AS min_rate, 100 AS max_rate "+
                       "    UNION ALL "+
                       "    SELECT 101 AS min_rate, 1000 AS max_rate "+
                       "    UNION ALL "+
                       "    SELECT 1001 AS min_rate, 10000 AS max_rate "+
                       "    UNION ALL "+
                       "    SELECT 10001 AS min_rate, 100000 AS max_rate "+
                       "    UNION ALL "+
                       "    SELECT 100001 AS min_rate, null AS max_rate) AS bin " +
                       "ON " +
                       "    (bin.min_rate <= c.ppd) "+
                       "AND "+
                       "    (((bin.max_rate IS NOT NULL) "+
                       "        AND " +
                       "        bin.max_rate >= c.ppd) " +
                       "    OR " +
                       "        bin.max_rate IS NULL) "+
                       "GROUP BY bin.min_rate, bin.max_rate "+
                       "ORDER BY bin.min_rate;";

        System.err.println(query);
        ResultSet rs = null;

        histogram.nextEntry();

        for (i = 0; i < slots.length; i++) {
            String name;

            if (i == 0) {
                name = slots[i] + " - " + slots[i+1];
            } else if (i == slots.length - 1) {
                name = slots[i] + " +";
            } else {
                name = slots[i] + " - " + (slots[i+1]-1);
            }

            histogram.addData(name, 0);
        }

        if (! histogram.downloadCurrent(dbr)) {
            rs = dbr.retrieve(query);

            while (rs.next())
            {
                int min_rate = rs.getInt(1);
                int max_rate = rs.getInt(2);
                long count = rs.getLong(3);
                String name;

                if (max_rate == 0 && min_rate != 0) {
                    name = min_rate + " +";
                } else if (max_rate == 0) {
                    name = min_rate + " - 1";
                } else {
                    name = min_rate + " - " + max_rate;
                }

                histogram.addData(name, count);
            }
            rs.close();
        }
        histogram.upload(dbr);

        dbr.close();

        System.out.println("<" + reportName + ">");
        System.out.println("  <start-date>" + startDateStr + "</start-date>");
        System.out.println("  <end-date>" + endDateStr + "</end-date>");
        histogram.output(System.out);
        System.out.println("</" + reportName + ">");
    }
}
