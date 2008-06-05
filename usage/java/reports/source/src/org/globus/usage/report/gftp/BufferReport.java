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

import java.text.SimpleDateFormat;

import java.util.Date;

public class BufferReport {
    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java BufferReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

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

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        while (ts.next()) {
            Date startD = ts.getTime();
            String startS = ts.getFormattedTime();
            ts.stepTime();

            bufferHist.nextEntry(startS, ts.getFormattedTime());
            blockHist.nextEntry(startS, ts.getFormattedTime());
            bandwidthHist.nextEntry(startS, ts.getFormattedTime());
            byteHist.nextEntry(startS, ts.getFormattedTime());
            packetHist.nextEntry(startS, ts.getFormattedTime());

            String startDate = ts.getFormattedTime();
            ResultSet rs;

            rs = dbr.retrieve(
                "SELECT bin.min_rate, COUNT(*) FROM "+
                "    (SELECT num_bytes "+
                "    FROM gftp_packets "+
                "    WHERE "+
                "        DATE(send_time) >= '" + dateFormat.format(startD) + "' "+
                "    AND "+
                "       DATE(send_time) < '" + dateFormat.format(ts.getTime()) + "' "+
                "    )" +
                "    AS c " +
                "INNER JOIN " +
                "    (" +
                getSlotBinsAsTable(byteHist) +
                "    ) as bin "+
                "ON "+
                "    (bin.min_rate <= c.num_bytes) "+
                "AND " + 
                "    (((bin.max_rate IS NOT NULL) " +
                "        AND bin.max_rate > c.num_bytes) " +
                "    OR bin.max_rate IS NULL)  "+
                "GROUP BY bin.min_rate;");

            while (rs.next()) {
                double numBytes = rs.getDouble(1);
                long count = rs.getLong(2);

                byteHist.addRangedData(numBytes, count);
            }

            rs = dbr.retrieve(
                "SELECT bin.min_rate, COUNT(*) FROM "+
                "    (SELECT block_size "+
                "    FROM gftp_packets "+
                "    WHERE "+
                "        DATE(send_time) >= '" + dateFormat.format(startD) + "' "+
                "    AND "+
                "       DATE(send_time) < '" + dateFormat.format(ts.getTime()) + "' "+
                "    )" +
                "    AS c " +
                "INNER JOIN "+
                "    (" +
                getSlotBinsAsTable(blockHist) +
                "    ) as bin "+
                "ON "+
                "    (bin.min_rate <= c.block_size) "+
                "AND " + 
                "    (((bin.max_rate IS NOT NULL) " +
                "        AND bin.max_rate > c.block_size) " +
                "    OR bin.max_rate IS NULL)  "+
                "GROUP BY bin.min_rate;");

            while (rs.next()) {
                double blockSize = rs.getDouble(1);
                long count = rs.getLong(2);

                blockHist.addRangedData(blockSize, count);
            }
            rs.close();

            rs = dbr.retrieve(
                "SELECT bin.min_rate, COUNT(*) FROM "+
                "    (SELECT buffer_size "+
                "    FROM gftp_packets "+
                "    WHERE "+
                "        DATE(send_time) >= '" + dateFormat.format(startD) + "' "+
                "    AND "+
                "       DATE(send_time) < '" + dateFormat.format(ts.getTime()) + "' "+
                "    )" +
                "    AS c " +
                "INNER JOIN "+
                "    (" +
                getSlotBinsAsTable(bufferHist) +
                "    ) as bin "+
                "ON "+
                "    (bin.min_rate <= c.buffer_size) "+
                "AND " +
                "    (((bin.max_rate IS NOT NULL) " +
                "        AND bin.max_rate > c.buffer_size) " +
                "    OR bin.max_rate IS NULL)  "+
                "GROUP BY bin.min_rate;");

            while (rs.next()) {
                double bufferSize = rs.getDouble(1);
                long count = rs.getLong(2);

                bufferHist.addRangedData(bufferSize, count);
            }
            rs.close();

            rs = dbr.retrieve(
                "SELECT bin.min_rate, COUNT(*) FROM "+
                "    (SELECT (num_bytes / EXTRACT(EPOCH from (end_time-start_time))) as transfer_rate "+
                "    FROM gftp_packets "+
                "    WHERE "+
                "        DATE(send_time) >= '" + dateFormat.format(startD) + "' "+
                "    AND "+
                "       DATE(send_time) < '" + dateFormat.format(ts.getTime()) + "' " +
                "    AND "+
                "        end_time > start_time "+
                "    AND "+
                "         num_bytes > 0) as c " +
                "INNER JOIN "+
                "    (" +
                getSlotBinsAsTable(bandwidthHist) +
                "    ) as bin "+
                "ON "+
                "    (bin.min_rate <= c.transfer_rate) "+
                "AND  "+
                "    (((bin.max_rate IS NOT NULL) " +
                "        AND bin.max_rate > c.transfer_rate) " +
                "    OR bin.max_rate IS NULL)  "+
                "GROUP BY bin.min_rate;");

            while (rs.next()) {
                double bandwidth = rs.getDouble(1);
                long count = rs.getLong(2);

                bandwidthHist.addRangedData(bandwidth, count);
            }

            rs = dbr.retrieve(
                    "SELECT COUNT(1) "+
                    "FROM gftp_packets "+
                    "WHERE " +
                    "    DATE(send_time) >= '" + dateFormat.format(startD) + "' " +
                    "AND " +
                    "    DATE(send_time) <  '" + dateFormat.format(ts.getTime()) + "';");
            while (rs.next()) {
                long transfers = rs.getLong(1);

                packetHist.addData("Number of Transfers", transfers);
            }
            rs.close();
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

    private static String getSlotBinsAsTable(HistogramParser parser) {
        int num_slots = parser.getNumSlots();
        String result = new String();
        long lastThreshold = parser.getSlotThreshold(0);

        for (int i = 1; i < num_slots; i++) {
            long threshold = parser.getSlotThreshold(i);

            result += "SELECT " +
                      Long.toString(lastThreshold) + " as min_rate, " + 
                      Long.toString(threshold) + " as max_rate " +
                      "UNION ALL ";
            lastThreshold = threshold;
        }
        result += "SELECT " +
                  Long.toString(lastThreshold) + " as min_rate, " +
                  "null as max_rate";
        return result;
    }

}
