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

            ResultSet rs;
            
            rs = dbr.retrieve(
                    "SELECT stor_or_retr, COUNT(*) " +
                    "FROM gftp_packets "+
                    "WHERE date(send_time) >= '" + startDate + "' " +
                    "  AND date(send_time) <  '" + ts.getTime() + "' " +
                    "GROUP BY stor_or_retr;");

            while (rs.next()) {
                int type = rs.getInt(1);
                int count = rs.getInt(2);

                if (type == 0) {
                    transferHist.addData("STOR", count);
                } else if (type == 1) {
                    transferHist.addData("RETR", count);
                } else if (type == 2) {
                    transferHist.addData("Other", count);
                }
            }
            rs.close();

            rs = dbr.retrieve(
                    "SELECT " +
                    "     SUBSTRING( "+
                    "         gftp_version, 1, POSITION( "+
                    "                              ' (' IN gftp_version) - 1) " +
                    "     AS version, COUNT(*) "+
                    "FROM gftp_packets "+
                    "WHERE date(send_time) >= '" + startDate + "' " +
                    "  AND date(send_time) <  '" + ts.getTime() + "' " +
                    "GROUP BY version;");

            while (rs.next()) {
                String version = rs.getString(1);
                int count = rs.getInt(2);

                versionHist.addData(version, count);
            }
            rs.close();

            rs = dbr.retrieve(
                    "SELECT ftp_return_code, COUNT(*) " +
                    "FROM gftp_packets "+
                    "WHERE date(send_time) >= '" + startDate + "' " +
                    "  AND date(send_time) <  '" + ts.getTime() + "' " +
                    "GROUP BY ftp_return_code;");

            while (rs.next()) {
                String ftp_return_code = rs.getString(1);
                int count = rs.getInt(2);

                responseHist.addData(ftp_return_code, count);
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
