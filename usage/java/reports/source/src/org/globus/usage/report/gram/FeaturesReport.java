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

import java.text.NumberFormat;
import java.text.DecimalFormat;

import java.util.Date;
import java.util.Locale;

import java.text.SimpleDateFormat;


public class FeaturesReport{
    
    public static void main (String [] args) throws Exception{
        String USAGE = "Usage: java JobFlagReport [options] <date (YYYY-MM-DD)> Enter -help for a list of options\n";

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
            } else if (args[i].equalsIgnoreCase("-help")) {
                System.err.println(USAGE);
                System.err.println(HELP);
                System.exit(1);
            } else {
                System.err.println("Unknown argument: " + args[i]);
                System.exit(1);
            }
        }

        String inputDate = args[args.length-1];

        DecimalFormat f = (DecimalFormat) NumberFormat.getInstance(Locale.US);
        f.setMaximumFractionDigits(3);

        TimeStep ts = new TimeStep (stepStr, n, inputDate);     
        System.out.println("<features-report>");

        int totalJobs;
        int JCEused;
        int FSIused;
        int FSOused;
        int FCUused;
        int CUHused;

        DatabaseRetriever dbr = new DatabaseRetriever();

        while(ts.next()){
            totalJobs = 0;
            JCEused = 0;
            FSIused = 0;
            FSOused = 0;
            FCUused = 0;
            CUHused = 0;

            String startDate = ts.getFormattedTime();
            Date startingTime = ts.getTime();
            
            ResultSet rs = dbr.retrieve(new String ("gram_packets"), new String [] {"Count(*)"},new String [] {"job_credential_endpoint_used"}, startingTime, ts.stepTime());
            rs.next();
            JCEused=rs.getInt(1);
   
            rs = dbr.retrieve(new String ("gram_packets"), new String [] {"Count(*)"},new String [] {"file_stage_in_used"}, startingTime, ts.getTime());   
            rs.next();
            FSIused=rs.getInt(1);
            
            rs = dbr.retrieve(new String ("gram_packets"), new String [] {"Count(*)"},new String [] {"file_stage_out_used"}, startingTime, ts.getTime());    
            rs.next();
            FSOused=rs.getInt(1);
            
            rs = dbr.retrieve(new String ("gram_packets"), new String [] {"Count(*)"},new String [] {"file_clean_up_used"}, startingTime, ts.getTime());
            rs.next();
            FCUused=rs.getInt(1);

            rs = dbr.retrieve(new String ("gram_packets"), new String [] {"Count(*)"},new String [] {"clean_up_hold_used"}, startingTime, ts.getTime());
            rs.next();
            CUHused=rs.getInt(1);

            rs = dbr.retrieve(new String("gram_packets"), new String[] {"Count(*)"}, startingTime,ts.getTime());
            rs.next();
            totalJobs=rs.getInt(1);

            rs.close();

                System.out.println(" <entry>");
                System.out.println("\t<start-date>" + startDate + "</start-date>");
                System.out.println("\t<end-date>" + ts.getFormattedTime() + "</end-date>");

                System.out.println("\t<total-jobs>"+totalJobs+"</total-jobs>");
                System.out.println("\t<job-endpoint-used>" + f.format(100.0*JCEused/totalJobs) + "</job-endpoint-used>");
                System.out.println("\t<file-stage-in-used>" + f.format(100.0*FSIused/totalJobs) +"</file-stage-in-used>");
                System.out.println("\t<file-stage-out-used>" + f.format(100.0*FSOused/totalJobs)+"</file-stage-out-used>");
                System.out.println("\t<file-clean-up-used>" + f.format(100.0*FCUused/totalJobs)+"</file-clean-up-used>");
                System.out.println("\t<clean-up-hold-used>" + f.format(100.0*CUHused/totalJobs) + "</clean-up-hold-used>");

                System.out.println(" </entry>");
            
        }
        dbr.close();
        System.out.println("</features-report>");
    }
}
