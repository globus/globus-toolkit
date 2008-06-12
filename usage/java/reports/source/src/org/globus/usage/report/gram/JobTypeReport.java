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
import org.globus.usage.report.common.PercentageHistogramParser;
import org.globus.usage.report.common.TimeStep;

import java.sql.ResultSet;

import java.text.SimpleDateFormat;

import java.util.Locale;

public class JobTypeReport {

    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java JobTypeReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

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
        PercentageHistogramParser jobtypeHistogram =
                new PercentageHistogramParser(
                    "GRAM4 JobTypes (% of total jobs)", "jobtypehistogram",
                    "JobType Distribution", ts);

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        String jobTypeNames[] = {
            "multiple", "single", "multiple", "mpi", "condor"
        };

        while (ts.next()) {
            String startDate = ts.getFormattedTime();
            System.err.println("STEP");
            String startTime = dateFormat.format(ts.getTime());
            String endTime = dateFormat.format(ts.stepTime());
            jobtypeHistogram.nextEntry();

            if (! jobtypeHistogram.downloadCurrent(dbr)) {
                ResultSet rs = dbr.retrieve(
                        "    SELECT job_type, COUNT(*) "+
                        "    FROM gram_packets " +
                        "        WHERE " +
                        "            send_time >= '" + startTime + "' " +
                        "        AND send_time < '" + endTime + "' " +
                        "    GROUP BY job_type;");

                while (rs.next()) {
                    int type = rs.getInt(1);
                    long count = rs.getLong(2);

                    jobtypeHistogram.addData(jobTypeNames[type], count);
                }
                rs.close();
            }
        }
        jobtypeHistogram.upload(dbr);
        dbr.close();

        System.out.println("<job-type-report>");
        jobtypeHistogram.output(System.out);
        System.out.println("</job-type-report>");
    }
}
