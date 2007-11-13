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
package org.globus.usage.report.rls;

import org.globus.usage.report.common.DatabaseRetriever;
import org.globus.usage.report.common.HistogramParser;
import org.globus.usage.report.common.TimeStep;

import java.sql.ResultSet;

import java.util.Date;
import java.util.Map;
import java.util.Iterator;

public class UptimeReport {

    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java UptimeReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

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

        HistogramParser typeHist = new HistogramParser(
                "Percent of RLS Deployments By Type (LRC, RLI, or Both)",
                "rlstypehistogram", "Percent of total deployments", n);

        HistogramParser uptimeHist = new HistogramParser(
                "Maximum Uptime of RLS Deployments",
                "rlsuptimehistogram", "Number of deployments", n);

        HistogramParser verHist = new HistogramParser(
                "Percent of RLS Deployments By Version",
                "rlsverhistogram", "Percent of total deployments", n);

        while (ts.next()) {
            Map rlss = new java.util.HashMap();
            
            Date startD = ts.getTime();
            String startS = ts.getFormattedTime();
            ts.stepTime();

            typeHist.nextEntry(startS, ts.getFormattedTime());
            uptimeHist.nextEntry(startS, ts.getFormattedTime());
            verHist.nextEntry(startS, ts.getFormattedTime());

            DatabaseRetriever dbr = new DatabaseRetriever();
            String startDate = ts.getFormattedTime();

            ResultSet rs = dbr.retrieve("rls_packets", new String[] {
                    "ip_address", "rls_version", "uptime", "lrc", "rli" },
                    startD, ts.getTime());
            while (rs.next()) {

                // Get raw data from resultset
                String ip = rs.getString(1);
                String ver = rs.getString(2);
                long uptime = rs.getLong(3);
                boolean lrc = rs.getBoolean(4);
                boolean rli = rs.getBoolean(5);

                // Find existing RLS entry or create new one
                RLSEntry rls;
                if (rlss.containsKey(ip)) {
                    rls = (RLSEntry) rlss.get(ip);
                }
                else {
                    rls = new RLSEntry();
                    rlss.put(ip, rls);
                }

                // Update replica count for RLS entry
                rls.ver = ver;
                rls.lrc = lrc;
                rls.rli = rli;
                if (rls.uptime < uptime)
                    rls.uptime = uptime;
            }

            // Produce stats
            int sizeRls = rlss.size();
            int cTypeBoth = 0;
            int cTypeLrc = 0;
            int cTypeRli = 0;
            int cTypeNone = 0;
            int cUp1H = 0; int t1h = 60*60;
            int cUp1D = 0; int t1d = 24*t1h;
            int cUp1M = 0; int t1m = 30*t1d;
            int cUp3M = 0; int t3m = 3*t1m;
            int cUp6M = 0; int t6m = 6*t1m;
            int cUpOver6M = 0;
            Map rlsVer = new java.util.HashMap();
            Iterator iter = rlss.keySet().iterator();
            while (iter.hasNext()) {
                Object key = iter.next();
                RLSEntry rls = (RLSEntry) rlss.get(key);
                
                // Update types
                if (rls.lrc && rls.rli)
                    cTypeBoth++;
                else if (rls.lrc)
                    cTypeLrc++;
                else if (rls.rli)
                    cTypeRli++;
                else
                    cTypeNone++;

                // Update uptimes
                if (rls.uptime < t1h)
                    cUp1H++;
                else if (rls.uptime < t1d)
                    cUp1D++;
                else if (rls.uptime < t1m)
                    cUp1M++;
                else if (rls.uptime < t3m)
                    cUp3M++;
                else if (rls.uptime < t6m)
                    cUp6M++;
                else
                    cUpOver6M++;

                // Update versions
                String ver = rls.ver;
                if (ver == null)
                    ver = "unknown";
                Count cVer = (Count) rlsVer.get(ver);
                if (cVer == null) {
                    cVer = new Count(1);
                    rlsVer.put(ver, cVer);
                }
                else {
                    cVer.increment();
                }
            }

            typeHist.addData("% Both", 100.0*cTypeBoth/sizeRls);
            typeHist.addData("% LRC", 100.0*cTypeLrc/sizeRls);
            typeHist.addData("% RLI", 100.0*cTypeRli/sizeRls);
            typeHist.addData("% Neither", 100.0*cTypeNone/sizeRls);

            uptimeHist.addData("Up to 1 hour", cUp1H);
            uptimeHist.addData("Up to 1 day", cUp1D);
            uptimeHist.addData("Up to 1 month", cUp1M);
            uptimeHist.addData("Up to 3 months", cUp3M);
            uptimeHist.addData("Up to 6 months", cUp6M);
            uptimeHist.addData("Over 6 months", cUpOver6M);

            iter = rlsVer.keySet().iterator();
            while (iter.hasNext()) {
                String ver = (String) iter.next();
                Count cVer = (Count) rlsVer.get(ver);
                verHist.addData(ver, 100.0*cVer.value/sizeRls);
            }

            rs.close();
            dbr.close();
        }
        System.out.println("<report>");
        typeHist.output(System.out);
        uptimeHist.output(System.out);
        verHist.output(System.out);
        System.out.println("</report>");
    }
}
