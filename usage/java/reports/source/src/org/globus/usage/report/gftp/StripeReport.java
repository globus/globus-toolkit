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
import org.globus.usage.report.common.TimeStep;

import java.sql.ResultSet;

import java.util.Date;

public class StripeReport {

    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java StripeReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

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

        TimeStep ts = new TimeStep(stepStr, n, inputDate);

        HistogramParser streamHist = new HistogramParser(
                "Number of Packets shown by Streams Used",
                "GFTPstreamhistogram",
                "Number of GFTP Packets with Given Number of Streams", n);

        HistogramParser stripeHist = new HistogramParser(
                "Number of Packets Shown by Stripes Used",
                "GFTPstripehistogram",
                "Number of GFTP Packets with Given Number of Stripes", n);

        DatabaseRetriever dbr = new DatabaseRetriever();

        while (ts.next()) {
            String startTime = ts.getFormattedTime();
            Date startDate = ts.getTime();
            ts.stepTime();

            streamHist.nextEntry(startTime, ts.getFormattedTime());
            stripeHist.nextEntry(startTime, ts.getFormattedTime());

            ResultSet rs = dbr.retrieve("gftp_packets", new String[] {
                    "num_streams", "num_stripes" }, startDate, ts.getTime());
            while (rs.next()) {
                streamHist.addData(rs.getString(1), 1);
                stripeHist.addData(rs.getString(2), 1);
            }
            rs.close();
        }
        dbr.close();
        System.out.println("<report>");
        streamHist.output(System.out);
        stripeHist.output(System.out);
        System.out.println("</report>");
    }
}
