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
import org.globus.usage.report.common.MultiPercentageHistogramParser;
import org.globus.usage.report.common.TimeStep;

import java.sql.ResultSet;

import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.Locale;

public class FeaturesReport {

    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java FeaturesReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

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
        MultiPercentageHistogramParser histogram = 
                new MultiPercentageHistogramParser(
                    "Percentage of GRAM4 Jobs Using Features",
                    "jobfeatureshistogram", "Job Features", ts);
            
        DatabaseRetriever dbr = new DatabaseRetriever();

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

        while (ts.next()) {
            String startTime = dateFormat.format(ts.getTime());
            String endTime = dateFormat.format(ts.stepTime());
            histogram.nextEntry();
            
            if (! histogram.downloadCurrent(dbr)) {
                ResultSet rs = dbr.retrieve(
                        "SELECT " +
                        "    SUM ( "+
                        "        CASE " +
                        "            WHEN job_credential_endpoint_used " +
                        "                THEN 1 " +
                        "            ELSE 0 " +
                        "        END), "+
                        "    SUM ( "+
                        "        CASE " +
                        "            WHEN file_stage_in_used " +
                        "                THEN 1 " +
                        "            ELSE 0 " +
                        "        END), "+
                        "    SUM ( "+
                        "        CASE " +
                        "            WHEN file_stage_out_used " +
                        "                THEN 1 " +
                        "            ELSE 0 " +
                        "        END), "+
                        "    SUM ( "+
                        "        CASE " +
                        "            WHEN file_clean_up_used " +
                        "                THEN 1 " +
                        "            ELSE 0 " +
                        "        END), "+
                        "    SUM ( "+
                        "        CASE " +
                        "            WHEN clean_up_hold_used " +
                        "                THEN 1 " +
                        "            ELSE 0 " +
                        "        END), " +
                        "     COUNT(*) " +
                        "FROM gram_packets " +
                        "    WHERE "+
                        "        DATE(send_time) >= '" + startTime + "' " +
                        "    AND "+
                        "        DATE(send_time) < '" + endTime + "';");

                rs.next();
                histogram.addData("job-endpoint-used", (double) rs.getInt(1));
                histogram.addData("file-stage-in-used", (double) rs.getInt(2));
                histogram.addData("file-stage-out-used", (double) rs.getInt(3));
                histogram.addData("file-clean-up-used", (double) rs.getInt(4));
                histogram.addData("clean-up-hold-used", (double) rs.getInt(5));
                histogram.setTotal(rs.getInt(6));
                rs.close();
            }
        }
        histogram.upload(dbr);
        dbr.close();
        System.out.println("<features-report>");
        histogram.output(System.out);
        System.out.println("</features-report>");
    }
}
