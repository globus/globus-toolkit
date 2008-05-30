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
package org.globus.usage.report.gftp;

import org.globus.usage.report.common.DatabaseRetriever;
import org.globus.usage.report.common.HistogramParser;
import org.globus.usage.report.common.IPEntry;
import org.globus.usage.report.common.TimeStep;
import java.sql.ResultSet;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Date;

public class HostReport {

    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java HostReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

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

        HistogramParser hostHist = new HistogramParser(
                "Number of Unique Hostnames Shown by Domain",
                "GFTPhosthistogram", "Number of Hosts", n);

        HistogramParser ipHist = new HistogramParser(
                "Number of Unique IPs Shown by Domain", "GFTPiphistogram",
                "Number of IP Addresses", n);

        while (ts.next()) {
            Date startD = ts.getTime();
            String startS = ts.getFormattedTime();
            ts.stepTime();

            hostHist.nextEntry(startS, ts.getFormattedTime());
            ipHist.nextEntry(startS, ts.getFormattedTime());

            ResultSet rs = dbr
                    .retrieve("gftp_packets",
                            new String[] { "DISTINCT(SUBSTRING(hostname, 1, POSITION('/' in hostname)-1))" }, startD, ts.getTime());

            while (rs.next()) {
                String hostname = rs.getString(1);
                int dotIndex;

                if ((dotIndex = hostname.lastIndexOf(".")) != -1) {
                    hostHist.addData(hostname.substring(dotIndex), 1);
                } else {
                    hostHist.addData("unknown", 1);
                }
            }
            rs.close();

            rs = dbr
                    .retrieve("gftp_packets",
                            new String[] { "DISTINCT(SUBSTRING(hostname, POSITION('/' in hostname)+1))" }, startD, ts.getTime());
                    
            while (rs.next()) {
                String ip = rs.getString(1);
                IPEntry ipentry = IPEntry.getIPEntry(ip);

                ipHist.addData(ipentry.getDomain(), 1);
            }
            rs.close();
        }
        dbr.close();
        System.out.println("<report>");
        ipHist.output(System.out);
        hostHist.output(System.out);
        System.out.println("</report>");
    }
}
