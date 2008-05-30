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
package org.globus.usage.report.rft;

import org.globus.usage.report.common.DatabaseRetriever;
import org.globus.usage.report.common.HistogramParser;
import org.globus.usage.report.common.TimeStep;

import java.sql.ResultSet;

import java.util.Date;

public class FileReport {

    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java FileReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

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

        HistogramParser fileHist = new HistogramParser(
                "Average Number of Files Transfered by a RFT Resource",
                "rftfilehistogram", "Number of Files", n);

        HistogramParser deleteHist = new HistogramParser(
                "Average Number of Files Deleted by a RFT Resource",
                "rftdeletehistogram", "Number of Files Deleted", n);

        HistogramParser byteHist = new HistogramParser(
                "Average Number of Bytes Transfered by a RFT Resource",
                "rftbytehistogram", "Bytes Transferred", n);

        HistogramParser typeHist = new HistogramParser(
                "Percent of Requests for Deletion vs. Transfer",
                "rfttypehistogram", "Percent of total requests", n);

        while (ts.next()) {
            int requests = 0;
            int delete = 0;
            int transfer = 0;
            int numFilesTransfer = 0;
            int numFilesDelete = 0;
            long numBytes = 0;

            Date startD = ts.getTime();
            String startS = ts.getFormattedTime();
            ts.stepTime();

            typeHist.nextEntry(startS, ts.getFormattedTime());
            deleteHist.nextEntry(startS, ts.getFormattedTime());
            fileHist.nextEntry(startS, ts.getFormattedTime());
            byteHist.nextEntry(startS, ts.getFormattedTime());

            DatabaseRetriever dbr = new DatabaseRetriever();
            String startDate = ts.getFormattedTime();

            ResultSet rs = dbr.retrieve(
                    "SELECT request_type, SUM(number_of_files), SUM(number_of_bytes), COUNT(*) "+
                    "    FROM rft_packets " +
                    "    WHERE DATE(send_time) >= '" + startD + "' " +
                    "      AND DATE(send_time) <  '" + ts.getTime() + "' " +
                    "    GROUP BY request_type;");

            while (rs.next()) {
                int request_type = rs.getInt(1);
                int number_of_files = rs.getInt(2);
                long number_of_bytes = rs.getLong(3);
                int count = rs.getInt(4);

                requests += count;

                if (request_type == 0) {
                    numFilesTransfer += number_of_files;
                    transfer += count;
                } else if (request_type == 1) {
                    numFilesDelete += number_of_files;
                    delete += count;
                }
                numBytes += number_of_bytes;
            }

            byteHist.addData("Number of Bytes", (double) numBytes / transfer);
            fileHist.addData("File Number Transferred",
                    (double) numFilesTransfer / transfer);
            deleteHist.addData("File Number Deleted", (double) numFilesDelete
                    / delete);
            typeHist.addData("% Transfers", 100.0 * transfer / requests);
            typeHist.addData("% Deletions", 100.0 * delete / requests);
            rs.close();
            dbr.close();
        }
        System.out.println("<report>");
        typeHist.output(System.out);
        deleteHist.output(System.out);
        byteHist.output(System.out);
        fileHist.output(System.out);
        System.out.println("</report>");
    }
}
