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
package org.globus.usage.report.common;

import org.globus.usage.report.common.DatabaseRetriever;
import org.globus.usage.report.common.HistogramParser;
import org.globus.usage.report.common.IPEntry;
import org.globus.usage.report.common.TimeStep;

import java.sql.ResultSet;

import java.util.Date;

public class DomainReport {

    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java DomainReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";
        String HELP = "Where [options] are:\n"
                + " -help                 Displays this help\n"
                + " -step <day|month>     Size of step [day]\n"
                + " -n <steps>            Number of steps to do [1]\n"
                + " -t <table>            Database table to process [gram_packets]\n"
                + " -c <host-column>      Column containing unique host identifier [ip_address]\n"
                + " -r <report-name>      Name of the report to create [domainhistogram\n";
        int n = 1;
        String stepStr = "day";
        String table = "gram_packets";
        String hostColumn = "ip_address";
        String reportName = "domainhistogram";
        String inputDate = null;

        for (int i = 0; i < args.length ;i++) {
            if (args[i].equals("-help") || args[i].equals("-h")) {
                System.err.println(USAGE);
                System.err.println(HELP);
                System.exit(0);
            } else if (args[i].equals("-step") && ++i < args.length) {
                stepStr = args[i];
            } else if (args[i].equals("-n") && ++i < args.length) {
                n = Integer.parseInt(args[i]);
            } else if (args[i].equals("-t") && ++i < args.length) {
                table = args[i];
            } else if (args[i].equals("-c") && ++i < args.length) {
                hostColumn = args[i];
            } else if (args[i].equals("-r") && ++i < args.length) {
                reportName = args[i];
            } else if (i == (args.length-1)) {
                inputDate = args[i];
            } else {
                System.err.println(USAGE);
                System.exit(1);
            }
        }

        DatabaseRetriever dbr = new DatabaseRetriever();
        TimeStep ts = new TimeStep(stepStr, n, inputDate);

        System.out.println("<report>");

        DomainHistogramParser ipReport = new DomainHistogramParser(
                "Number of Unique IP Addresses by Domain",
                reportName, "Number of Unique IP Addresses", ts);

        while (ts.next()) {
            Date startTime = ts.getTime();
            ts.stepTime();

            ipReport.nextEntry();

            if (!ipReport.downloadCurrent(dbr)) {
                ResultSet rs = dbr.retrieve(table,
                        new String[] { "DISTINCT ip_address" }, startTime, ts.getTime());

                while (rs.next()) {
                    String ip = rs.getString(1);
                    int idx = ip.lastIndexOf("/");
                    if (idx > 0) {
                        ip = ip.substring(idx);
                    }
                    ipReport.addData(ip);
                }
                rs.close();
            }
        }
        ipReport.upload(dbr);
        dbr.close();
        ipReport.output(System.out);
        System.out.println("</report>");
    }
}
