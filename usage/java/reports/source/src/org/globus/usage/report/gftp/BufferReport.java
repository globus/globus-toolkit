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

public class BufferReport {

    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java JobFlagReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

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

        HistogramParser bufferHist = new HistogramParser("TCP Buffer Size",
                "GFTPtcphistogram", n, "buffer");

        HistogramParser blockHist = new HistogramParser("Block Size",
                "GFTPblockhistogram", n, "block");

        HistogramParser byteHist = new HistogramParser("Size of Transfer",
                "GFTPbytehistogram", n, "byte");

        HistogramParser bandwidthHist = new HistogramParser(
                "Amount of Bandwidth", "GFTPbandwidthhistogram", n, "bandwidth");

        HistogramParser packetHist = new HistogramParser("Transfer Number",
                "GFTPpackethistogram", "Number of GFTP Transfers", n);

        long packetNumber;
        double bandWidth;
        long timeDiff;

        while (ts.next()) {
            Date startD = ts.getTime();
            String startS = ts.getFormattedTime();
            ts.stepTime();

            bandWidth = 0;
            packetNumber = 0;
            timeDiff = 0;

            bufferHist.nextEntry(startS, ts.getFormattedTime());
            blockHist.nextEntry(startS, ts.getFormattedTime());
            bandwidthHist.nextEntry(startS, ts.getFormattedTime());
            byteHist.nextEntry(startS, ts.getFormattedTime());
            packetHist.nextEntry(startS, ts.getFormattedTime());

            String startDate = ts.getFormattedTime();
            ResultSet rs = dbr.retrieve("gftp_packets", new String[] {
                    "num_bytes", "start_time", "end_time", "block_size",
                    "buffer_size" }, startD, ts.getTime());
            while (rs.next()) {
                bufferHist.addRangedData(rs.getDouble(5), 1);
                blockHist.addRangedData(rs.getDouble(4), 1);
                packetNumber++;
                byteHist.addRangedData(rs.getLong(1), 1);
                timeDiff = rs.getTimestamp(3).getTime()
                        - rs.getTimestamp(2).getTime();

                if (timeDiff > 0 || rs.getLong(1) != 0) {
                    bandWidth = (double) rs.getLong(1) / (timeDiff / 1000.0);
                    bandwidthHist.addRangedData(bandWidth, 1);
                }
            }
            rs.close();
            packetHist.addData("Number of Transfers", packetNumber);
        }
        dbr.close();
        System.out.println("<report>");
        packetHist.output(System.out);
        byteHist.output(System.out);
        bandwidthHist.output(System.out);
        blockHist.output(System.out);
        bufferHist.output(System.out);
        System.out.println("</report>");
    }
}
