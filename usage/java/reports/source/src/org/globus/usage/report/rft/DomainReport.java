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
import org.globus.usage.report.common.IPEntry;
import org.globus.usage.report.common.TimeStep;

import java.sql.ResultSet;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Date;

public class DomainReport{

    public static void main (String [] args) throws Exception {
        String USAGE = "Usage: java SchedulerReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

        String HELP = "Where [options] are:\n"+
            " -help                 Displays help\n"+
            " -step <day|month>     Specifies size of step (day by default)\n"+
            " -n <steps>            Specifies number of steps to do\n";

        if (args.length == 0){
            System.err.println(USAGE);
            System.exit(1);
        }
        else if (args.length == 1 && args[0].equalsIgnoreCase("-help")){
            System.err.println(USAGE);
            System.err.println(HELP);
            System.exit(1);
        }

        int n = 1;
        String stepStr = "day";

        for (int i=0;i<args.length-1;i++){
            if (args[i].equals("-n")) {
                n = Integer.parseInt(args[++i]);
            }
            else if (args[i].equals("-step")) {
                stepStr = args[++i];
            }
            else if (args[i].equalsIgnoreCase("-help")) {
                System.err.println(USAGE);
                System.err.println(HELP);
                System.exit(1);
            } else {
                System.err.println("Unknown argument: " + args[i]);
                System.exit(1);
            }
        }
        String inputDate = args[args.length-1];
        
        DatabaseRetriever dbr = new DatabaseRetriever();

        TimeStep ts = new TimeStep (stepStr, n, inputDate);

        System.out.println("<report>");

        HistogramParser ipReport = new HistogramParser("Number of Unique IP Addresses Using RFT Broken Down by Domain", "rftiphistogram", "Number of Unique IP Addresses", n);
        HistogramParser domainReport = new HistogramParser("Total RFT Resources Created Shown by Domain", "rftdomainhistogram", "Number of Resources Created", n);

        while (ts.next()){
            HashMap iptracker = new HashMap();

            String startDate = ts.getFormattedTime();
            Date startTime = ts.getTime();
            ts.stepTime();

            ipReport.nextEntry(startDate, ts.getFormattedTime());
            domainReport.nextEntry(startDate, ts.getFormattedTime());

            ResultSet rs = dbr.retrieve("rft_packets",new String [] {"ip_address"}, startTime, ts.getTime());
           
            while(rs.next()){
                IPEntry ipEntry = IPEntry.getIPEntry(rs.getString(1));
                iptracker.put(rs.getString(1),"");
                domainReport.addData(ipEntry.getDomain(), 1);
            }
            
            Iterator ipIterator = iptracker.keySet().iterator();
            while(ipIterator.hasNext())
                {
                    IPEntry ipEntry = IPEntry.getIPEntry((String)ipIterator.next());
                    ipReport.addData(ipEntry.getDomain(),1);
                }
            rs.close();
        }
        dbr.close();
        ipReport.output(System.out);
        domainReport.output(System.out);
    System.out.println("</report>");
}
}
