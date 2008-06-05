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
import org.globus.usage.report.common.HistogramParser;
import org.globus.usage.report.common.IPEntry;
import org.globus.usage.report.common.IPTable;
import org.globus.usage.report.common.TimeStep;

import java.sql.ResultSet;

import java.text.SimpleDateFormat;

import java.util.Date;

public class DomainReport {

    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java DomainReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

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

        HistogramParser internalReport = new HistogramParser(
                "Internal MCS/ISI packets recieved", "internalhistogram",
                "% of Jobs from MCS/ISI", ts);
        HistogramParser domainReport = new HistogramParser(
                "Total Jobs Shown by Domain", "domainhistogram",
                "Number of Jobs", ts);

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

        System.out.println("<report>");

        while (ts.next()) {
            int totalJobs = 0;
            int isiJobs = 0;
            int mcsJobs = 0;

            String startDate = ts.getFormattedTime();
            Date startTime = ts.getTime();
            ts.stepTime();

            internalReport.nextEntry();
            domainReport.nextEntry();

            ResultSet rs = dbr.retrieve(
                    "SELECT ip_address, COUNT(*) " +
                    "FROM gram_packets " +
                    "WHERE DATE(send_time) >= '" + dateFormat.format(startTime) + "' " +
                    "AND DATE(send_time) < '" + dateFormat.format(ts.getTime()) + "' " +
                    "GROUP BY ip_address;");

            while (rs.next()) {
                String ip_address = rs.getString(1);
                int job_count = rs.getInt(2);
                IPEntry ipEntry = IPEntry.getIPEntry(ip_address);
                String domain = ipEntry.getDomain();

                totalJobs += job_count;
                if (domain.equals("ISI")) {
                    isiJobs += job_count;
                } else if (domain.equals("MCS")) {
                    mcsJobs += job_count;
                }
                domainReport.addData(domain, job_count);
            }

            internalReport.addData("ISI", 100.0 * isiJobs / totalJobs);
            internalReport.addData("MCS", 100.0 * mcsJobs / totalJobs);
        }
        internalReport.output(System.out);
        domainReport.output(System.out);
        System.out.println("</report>");
    }
}
