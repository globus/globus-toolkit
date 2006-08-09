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

import org.globus.usage.report.common.Database;
import org.globus.usage.report.common.DatabaseRetriever;
import org.globus.usage.report.common.HistogramParser;
import org.globus.usage.report.common.IPEntry;
import org.globus.usage.report.common.IPTable;
import org.globus.usage.report.common.Slotter;
import org.globus.usage.report.common.TimeStep;

import java.sql.ResultSet;

import java.util.HashMap;
import java.util.Map;
import java.util.Iterator;
import java.util.Date;

import java.io.PrintStream;

public class SchedulerReport{
    
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

        String [] schedulerNames = {"Fork", "Condor", "PBS", "LSF", "Loadleveler", "SGE"};

        HistogramParser jobHist = new HistogramParser("Total Jobs by Scheduler Used", "jobhistogram","Total Jobs Shown by Scheduler Used", n);

        while (ts.next()){
            int totalJobs = 0;
            IPTable iptracker;
        
            String startDate = ts.getFormattedTime();
            Date startTime = ts.getTime();

            ts.stepTime();

            jobHist.nextEntry(startDate, ts.getFormattedTime());

            ResultSet rs = dbr.retrieve(new String ("gram_packets"), new String [] {"Count(*)"}, startTime, ts.getTime());

            rs.next();
            totalJobs+=rs.getInt(1);

            System.out.println(" <entry>");
            System.out.println("\t<start-date>" + startDate + "</start-date>");
            System.out.println("\t<end-date>" + ts.getFormattedTime() + "</end-date>");
            System.out.println("\t<total-jobs>" + totalJobs + "</total-jobs>");
            
            for (int i=0; i<6; i++)
            {
                int x=0;
                iptracker = new IPTable();
                 System.out.println("\t<scheduler>");
                 System.out.println("\t\t<name>"+schedulerNames[i]+"</name>");
                 System.out.println("\t\t<index>"+(i+1)+"</index>");
                 
                 rs = dbr.retrieve(new String ("gram_packets"), new String [] {"Count(*)"}, new String [] {"scheduler_type LIKE '"+schedulerNames[i]+"%'"}, startTime, ts.getTime());
                 rs.next();
                 
                 System.out.println("\t\t<jobs>"+rs.getInt(1)+"</jobs>");
                 jobHist.addData(schedulerNames[i],rs.getInt(1));

                 rs = dbr.retrieve(new String ("gram_packets"), new String [] {"DISTINCT ip_address"},  new String [] {"scheduler_type LIKE '%"+schedulerNames[i]+"%'"}, startTime, ts.getTime());
                 
                 while (rs.next()){
                     IPEntry ipEntry = IPEntry.getIPEntry(rs.getString(1));
                     iptracker.addAddress(rs.getString(1));
                     iptracker.addDomain(ipEntry.getDomain());
                 }
                System.out.println("\t\t<unique-domains>"+iptracker.getDomains().size()+"</unique-domains>");
                iptracker.output(System.out, "\t\t");
                System.out.println("\t</scheduler>");
            }
            System.out.println("</entry>");
            rs.close();
        }
        dbr.close();
        jobHist.output(System.out);
        System.out.println("</report>");
    }
}
