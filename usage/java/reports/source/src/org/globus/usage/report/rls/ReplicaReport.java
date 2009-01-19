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

public class ReplicaReport {

    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java ReplicaReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

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

        HistogramParser replicaHist = new HistogramParser(
                "Total Number of Replicas Registered in LRCs",
                "rlslrcreplicahistogram", "Number of Replicas", n);

        HistogramParser mappingHist = new HistogramParser(
                "Total Number of Mappings Registered in LRCs",
                "rlslrcmappinghistogram", "Number of Mappings", n);

        HistogramParser scaleHist = new HistogramParser(
                "Scale of LRCs (between empty and over 1M entries)",
                "rlslrcscalehistogram", "Number of LRCs", n);

        while (ts.next()) {
            Map lrcs = new java.util.HashMap();
            int numLrcLFNs = 0;
            int numLrcPFNs = 0;
            int numLrcMAPs = 0;
            int num1M = 0;
            int num100G = 0;
            int num10G = 0;
            int num1G = 0;
            int num100 = 0;
            int numSub100 = 0;
            int numEmpty = 0;
            
            Date startD = ts.getTime();
            String startS = ts.getFormattedTime();
            ts.stepTime();

            replicaHist.nextEntry(startS, ts.getFormattedTime());
            mappingHist.nextEntry(startS, ts.getFormattedTime());
            scaleHist.nextEntry(startS, ts.getFormattedTime());

            DatabaseRetriever dbr = new DatabaseRetriever();
            String startDate = ts.getFormattedTime();

            ResultSet rs = dbr.retrieve("rls_packets", new String[] {
                    "ip_address", "lfn", "pfn", "mappings" },
                    startD, ts.getTime());
            while (rs.next()) {

                // Get raw data from resultset
                String ip = rs.getString(1);
                int lfns = rs.getInt(2);
                int pfns = rs.getInt(3);
                int maps = rs.getInt(4);

                // Find existing RLS entry or create new one
                RLSEntry lrc;
                if (lrcs.containsKey(ip)) {
                    lrc = (RLSEntry) lrcs.get(ip);
                }
                else {
                    lrc = new RLSEntry();
                    lrcs.put(ip, lrc);
                }

                // Update replica count for RLS entry
                if (lrc.lfn < lfns)
                    lrc.lfn = lfns;
                if (lrc.pfn < pfns)
                    lrc.pfn = pfns;
                if (lrc.map < maps)
                    lrc.map = maps;
            }

            // Produce stats
            Iterator iter = lrcs.keySet().iterator();
            while (iter.hasNext()) {
                Object key = iter.next();
                RLSEntry lrc = (RLSEntry) lrcs.get(key);
                
                int tot = lrc.lfn + lrc.pfn;
                
                numLrcLFNs += lrc.lfn;
                numLrcPFNs += lrc.pfn;
                numLrcMAPs += lrc.map;

                if (tot == 0)
                    numEmpty++;
                else if (tot > 1000000)
                    num1M++;
                else if (tot > 100000)
                    num100G++;
                else if (tot > 10000)
                    num10G++;
                else if (tot > 1000)
                    num1G++;
                else if (tot > 100)
                    num100++;
                else
                    numSub100++;
            }

            replicaHist.addData("LFNs", numLrcLFNs);
            replicaHist.addData("PFNs", numLrcPFNs);
            mappingHist.addData("Mappings", numLrcMAPs);
            scaleHist.addData("Over 1M Entries", num1M);
            scaleHist.addData("Over 100K Entries", num100G);
            scaleHist.addData("Over 10K Entries", num10G);
            scaleHist.addData("Over 1K Entries", num1G);
            scaleHist.addData("Over 100 Entries", num100);
            scaleHist.addData("Under 100 Entries", numSub100);
            scaleHist.addData("Empty", numEmpty);

            rs.close();
            dbr.close();
        }
        System.out.println("<report>");
        replicaHist.output(System.out);
        mappingHist.output(System.out);
        scaleHist.output(System.out);
        System.out.println("</report>");
    }
}
