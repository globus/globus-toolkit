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
import org.globus.usage.report.common.MultiPercentageHistogramParser;
import org.globus.usage.report.common.TimeStep;

import java.sql.ResultSet;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.Locale;

public class ErrorReport {

    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java ErrorReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

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

        DecimalFormat f = (DecimalFormat) NumberFormat.getInstance(Locale.US);
        f.setMaximumFractionDigits(3);

        String[] faultNames = { "FAULT_CLASS_UNKNOWN",
                "FAULT_CLASS_CREDENTIAL_SERIALIZATION",
                "FAULT_CLASS_EXECUTION_FAILED", "FAULT_CLASS_FAULT",
                "FAULT_CLASS_FILE_PERMISSIONS",
                "FAULT_CLASS_INSUFFICIENT_CREDENTIALS", "FAULT_CLASS_INTERNAL",
                "FAULT_CLASS_INVALID_CREDENTIALS", "FAULT_CLASS_INVALID_PATH",
                "FAULT_CLASS_SERVICE_LEVEL_AGREEMENT", "FAULT_CLASS_STAGING",
                "FAULT_CLASS_UNSUPPORTED_FEATURE" };

        TimeStep ts = new TimeStep(stepStr, n, inputDate);

        DatabaseRetriever dbr = new DatabaseRetriever();

        HistogramParser gt2hist = new HistogramParser("Breakdown of GT2 Codes",
                "gt2histogram", "Jobs with Each Error code", ts);

        HistogramParser faulthist = new HistogramParser(
                "Breakdown of Fault Classes", "faulthistogram",
                "Number of Jobs with Fault Class", ts);
        MultiPercentageHistogramParser percentFaultHist =
                new MultiPercentageHistogramParser(
                    "Percentage of Jobs With Error or Fault Codes",
                    "percentfailedhistogram", "Percentage Failed", ts);

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

        while (ts.next()) {
            Date startTime = ts.getTime();
            String startDate = ts.getFormattedTime();
            ts.stepTime();

            gt2hist.nextEntry();
            faulthist.nextEntry();
            percentFaultHist.nextEntry();

            int totalJobs = 0;
            int gt2Jobs = 0;
            int faultJobs = 0;

            boolean gt2histCached = gt2hist.downloadCurrent(dbr);
            boolean faulthistCached = faulthist.downloadCurrent(dbr);
            boolean percentFailedCached = percentFaultHist.downloadCurrent(dbr);

            if (! (gt2histCached && faulthistCached && percentFailedCached)) {
                ResultSet rs = dbr.retrieve(
                        "SELECT gt2_error_code, fault_class, COUNT(*) "+
                        "    FROM gram_packets "+
                        "    WHERE DATE(send_time) >= '" + dateFormat.format(startTime) + "' "+
                        "        AND DATE(send_time) < '" + dateFormat.format(ts.getTime()) + "' "+
                        "    GROUP BY gt2_error_code, fault_class ;");
                while (rs.next()) {
                    int gt2_error_code = rs.getInt(1);
                    int fault_class = rs.getInt(2);
                    int jobs = rs.getInt(3);

                    totalJobs += jobs;
                    if ((!gt2histCached) && gt2_error_code != 0) {
                        gt2hist.addData(Integer.toString(gt2_error_code), jobs);
                    }
                    if ((!percentFailedCached) && gt2_error_code != 0) {
                        percentFaultHist.addData("GT2 Error Code", jobs);
                    }
                    if ((!faulthistCached) && fault_class != 0) {
                        faulthist.addData(faultNames[fault_class], jobs);
                    }
                    if ((!percentFailedCached) && fault_class != 0) {
                        percentFaultHist.addData("Fault Class", jobs);
                    }
                }
                rs.close();
                percentFaultHist.setTotal(totalJobs);
            }
        }
        gt2hist.upload(dbr);
        faulthist.upload(dbr);
        percentFaultHist.upload(dbr);
        dbr.close();

        System.out.println("<report>");
        gt2hist.output(System.out);
        faulthist.output(System.out);
        percentFaultHist.output(System.out);
        System.out.println("</report>");
    }
}
