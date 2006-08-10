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

public class ResponseReport {

    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java ResponseReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

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

        HistogramParser transferHist = new HistogramParser(
                "Number of Packets Shown by Transfer Type",
                "GFTPtransferhistogram",
                "Number of GFTP Packets with Given Transfer Type", n);

        HistogramParser responseHist = new HistogramParser(
                "Number of Packets Shown by FTP Reponse Code",
                "GFTPresponsehistogram",
                "Number of GFTP Packets with Given Response Code", n);

        HistogramParser versionHist = new HistogramParser(
                "Number of Packets shown by GFTP Version",
                "GFTPversionhistogram", "Number of Packets of Given Version", n);

        DatabaseRetriever dbr = new DatabaseRetriever();

        while (ts.next()) {
            String startTime = ts.getFormattedTime();
            Date startDate = ts.getTime();
            ts.stepTime();

            versionHist.nextEntry(startTime, ts.getFormattedTime());
            transferHist.nextEntry(startTime, ts.getFormattedTime());
            responseHist.nextEntry(startTime, ts.getFormattedTime());

            ResultSet rs = dbr.retrieve("gftp_packets", new String[] {
                    "gftp_version", "stor_or_retr", "ftp_return_code" },
                    startDate, ts.getTime());
            while (rs.next()) {
                versionHist.addData(rs.getString(1).substring(0,
                        rs.getString(1).indexOf("(")), 1);

                if (rs.getInt(2) == 0) {
                    transferHist.addData("STOR", 1);
                } else if (rs.getInt(2) == 1) {
                    transferHist.addData("RETR", 1);
                } else if (rs.getInt(2) == 2) {
                    transferHist.addData("Other", 1);
                }

                responseHist.addData(rs.getString(3), 1);
            }
            rs.close();
        }
        dbr.close();
        System.out.println("<report>");
        versionHist.output(System.out);
        transferHist.output(System.out);
        responseHist.output(System.out);
        System.out.println("</report>");
    }
}
