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
package org.globus.usage.report.gram;

import org.globus.usage.report.common.DatabaseRetriever;
import org.globus.usage.report.common.DomainHistogramParser;
import org.globus.usage.report.common.HistogramParser;
import org.globus.usage.report.common.TimeStep;

import java.sql.ResultSet;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;

public class SchedulerReport {

    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java SchedulerReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

        String HELP = "Where [options] are:\n"
                + " -help                 Displays help\n"
                + " -step <day|month>     Specifies size of step (day by default)\n"
                + " -n <steps>            Specifies number of steps to do\n";

        if (args.length == 0) {
            System.err.println(USAGE);
            System.exit(1);
        } else if (args.length == 1 && args[0].equalsIgnoreCase("-help")) {
            System.err.println(USAGE);
            System.err.println(HELP);
            System.exit(1);
        }

        int n = 1;
        String stepStr = "day";

        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equals("-n")) {
                n = Integer.parseInt(args[++i]);
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

        String inputDate = args[args.length - 1];

        DatabaseRetriever dbr = new DatabaseRetriever();

        TimeStep ts = new TimeStep(stepStr, n, inputDate);

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        Date queryStartDate = dateFormat.parse(inputDate);
        Calendar queryCalendar = new java.util.GregorianCalendar();
        queryCalendar.setTime(queryStartDate);
        queryCalendar.add(stepStr.equals("day") ? Calendar.DATE : Calendar.MONTH, n);
        Date queryEndDate = queryCalendar.getTime();

        ResultSet rs = dbr.retrieve(new String("gram_packets"),
                    new String[] { "DISTINCT LOWER(scheduler_type)" }, 
                    queryStartDate, queryEndDate);
        Vector<String> schedulerNames = new Vector(10);
        while (rs.next()) {
            schedulerNames.add(rs.getString(1));
        }

        HashMap <String, HistogramParser> ipHistHash =
            new HashMap<String, HistogramParser>();
        HashMap <String, DomainHistogramParser> domainHistHash =
            new HashMap<String, DomainHistogramParser>();

        for (int i = 0; i < schedulerNames.size(); i++) {
            String scheduler = schedulerNames.get(i);
            ipHistHash.put(scheduler,
                new HistogramParser(
                    "Jobs (" + scheduler + ") per IP address",
                    scheduler + "iphistogram",
                    "Jobs by IP Address", ts));
            domainHistHash.put(scheduler,
                new DomainHistogramParser(
                    "Jobs (" + scheduler + ") per Domain",
                    scheduler + "domainhistogram",
                    "Jobs by Domain", ts));
        }

        HistogramParser jobHist = new HistogramParser(
                "Total Jobs by Scheduler Used", "jobhistogram",
                "Total Jobs Shown by Scheduler Used", ts);

        while (ts.next()) {
            int totalJobs = 0;

            String startDate = ts.getFormattedTime();
            Date startTime = ts.getTime();

            ts.stepTime();

            jobHist.nextEntry();

            boolean jobHistCached = jobHist.downloadCurrent(dbr);
            boolean allCached = jobHistCached;
            HashMap<String, Boolean> histCached =
                    new HashMap<String, Boolean>();
            HashMap<String, Boolean> domainHistCached =
                    new HashMap<String, Boolean>();

            for (int i = 0; i < schedulerNames.size(); i++) {
                String scheduler = schedulerNames.get(i);
                HistogramParser dh = ipHistHash.get(scheduler);
                dh.nextEntry();

                if (dh.downloadCurrent(dbr)) {
                    histCached.put(scheduler, Boolean.TRUE);
                } else {
                    histCached.put(scheduler, Boolean.FALSE);
                    allCached = false;
                }

                dh = domainHistHash.get(scheduler);
                dh.nextEntry();

                if (dh.downloadCurrent(dbr)) {
                    domainHistCached.put(scheduler, Boolean.TRUE);
                } else {
                    domainHistCached.put(scheduler, Boolean.FALSE);
                    allCached = false;
                }
            }

            if (! allCached) {
                rs = dbr.retrieve(
                        "SELECT LOWER(scheduler_type), ip_address, COUNT(*) " +
                        "FROM gram_packets " +
                        "WHERE DATE(send_time) >= '" + dateFormat.format(startTime) +"' " +
                        "AND DATE(send_time) < '" + dateFormat.format(ts.getTime()) + "' " +
                        "GROUP BY LOWER(scheduler_type), ip_address;");

                while (rs.next()) {
                    String scheduler = rs.getString(1);
                    String ipAddress = rs.getString(2);
                    long count = rs.getLong(3);

                    if (!jobHistCached) {
                        jobHist.addData(scheduler, count);
                    }
                    if (! histCached.get(scheduler).booleanValue()) {
                        ipHistHash.get(scheduler).addData(ipAddress, count);
                    }
                    if (! domainHistCached.get(scheduler).booleanValue()) {
                        domainHistHash.get(scheduler).addData(ipAddress, count);
                    }
                }
            }
            rs.close();
        }
        jobHist.upload(dbr);
        for (int i = 0; i < schedulerNames.size(); i++) {
            ipHistHash.get(schedulerNames.get(i)).upload(dbr);
            domainHistHash.get(schedulerNames.get(i)).upload(dbr);
        }

        System.out.println("<report>");
        jobHist.output(System.out);
        for (int i = 0; i < schedulerNames.size(); i++) {
            ipHistHash.get(schedulerNames.get(i)).output(System.out);
        }
        for (int i = 0; i < schedulerNames.size(); i++) {
            domainHistHash.get(schedulerNames.get(i)).output(System.out);
        }
        System.out.println("</report>");
        dbr.close();
    }
}
