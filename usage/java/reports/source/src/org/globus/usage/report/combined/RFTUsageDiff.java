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
package org.globus.usage.report.combined;

import org.globus.usage.report.common.DatabaseRetriever;
import org.globus.usage.report.common.HistogramParser;
import org.globus.usage.report.common.IPEntry;
import org.globus.usage.report.common.TimeStep;

import java.sql.ResultSet;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Date;
import java.util.Calendar;
import java.text.SimpleDateFormat;
import java.sql.Timestamp;

public class RFTUsageDiff extends SlotWeekHelper {

    static class FreqDist {
        public long firstSendTime = -1;
        public long lastSendTime = -1;

        private int size = 100;

        public FreqDist(long sendTime)
        {
            this.firstSendTime = sendTime;
            this.lastSendTime = sendTime;
        }

        /* store the earliest and latest times only */
        public void checkSendTime(long sendTime)
        {
            if (sendTime < this.firstSendTime)
            {
                this.firstSendTime = sendTime;
            }
            if (sendTime > this.lastSendTime)
            {
                this.lastSendTime = sendTime;
            }
        }
    }

    public RFTUsageDiff()
    {
        initializeSlots();
    }

    public void computeTimeDiff(FreqDist fDist, String ipAddr)
    {
        long curDiff = (fDist.lastSendTime - fDist.firstSendTime);
/*         System.out.println("<timediff ip=\"" + ipAddr + " diff=\"" + ((curDiff / 1000) / SEC_PER_WEEK) + " weeks\"/>"); */
        Slot slot = getSlot(curDiff / 1000);
        slot.increment();
    }


    public static void main(String[] args) throws Exception {
        String USAGE = "Usage: java RFTUsageDiff [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

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
        String baseQueryStart = "select send_time,ip_address from ";
        String table = "rft_packets";
        String baseQueryEnd = " where ";

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

        // parse step info
        int step = -1;
        if (stepStr.equalsIgnoreCase("day")) {
            step = Calendar.DATE;
        } else if (stepStr.equalsIgnoreCase("month")) {
            step = Calendar.MONTH;
        } else {
            System.err.println("Unsupported step: " + stepStr);
            System.exit(2);
        }

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        RFTUsageDiff fDistGraph = new RFTUsageDiff();

        DatabaseRetriever dbr = new DatabaseRetriever();

        /* form the query */
        Date date = dateFormat.parse(inputDate);

        Calendar calendar = dateFormat.getCalendar();
        if (n < 0) {
            calendar.add(step, n);
            n = -n;
        }
        Date sDate = calendar.getTime();
        calendar.add(step, n);
        Date endDate = calendar.getTime();
            
        String startDateStr = dateFormat.format(sDate);
        String endDateStr = dateFormat.format(endDate);
        String timeFilter = "DATE(send_time) >= '" + startDateStr + 
            "' and DATE(send_time) < '" + endDateStr + "'";
                
        String query = baseQueryStart + table + baseQueryEnd + timeFilter
            + " order by send_time";

        System.out.println("<combined-rftusagediff-report>");
        System.out.println("  <start-date>" + startDateStr + "</start-date>");
        System.out.println("  <end-date>" + endDateStr + "</end-date>");

        ResultSet rs = null;

        HashMap ipMap = new HashMap();

        rs = dbr.retrieve(query);

        while (rs.next())
        {
            Timestamp tmpDate = rs.getTimestamp(1);
            String ipAddr = rs.getString(2);

            long milliSecs = tmpDate.getTime();

            FreqDist fDist = (FreqDist)ipMap.get((Object)ipAddr);
            if (fDist == null)
            {
                fDist = new FreqDist(milliSecs);
                ipMap.put((Object)ipAddr, fDist);
            }
            else
            {
                fDist.checkSendTime(milliSecs);
            }
        }
        rs.close();

        /* analyze the freq dist data here and generate the report output */
        Iterator key = ipMap.keySet().iterator();
        Iterator value = ipMap.values().iterator();
            
        while(key.hasNext() && value.hasNext())
        {
            String ipAddr = (String)key.next();
            FreqDist fDist = (FreqDist)value.next();
            fDistGraph.computeTimeDiff(fDist, ipAddr);
        }

        fDistGraph.output(System.out);

        dbr.close();
        System.out.println("</combined-rftusagediff-report>");
    }
}
