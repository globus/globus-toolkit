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
import org.globus.usage.report.common.TimeStep;

import java.sql.ResultSet;

import java.text.NumberFormat;
import java.text.DecimalFormat;

import java.util.Date;
import java.util.Locale;

public class ErrorReport{
    
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

        String [] faultNames = {"FAULT_CLASS_UNKNOWN","FAULT_CLASS_CREDENTIAL_SERIALIZATION","FAULT_CLASS_EXECUTION_FAILED","FAULT_CLASS_FAULT","FAULT_CLASS_FILE_PERMISSIONS","FAULT_CLASS_INSUFFICIENT_CREDENTIALS","FAULT_CLASS_INTERNAL","FAULT_CLASS_INVALID_CREDENTIALS","FAULT_CLASS_INVALID_PATH","FAULT_CLASS_SERVICE_LEVEL_AGREEMENT","FAULT_CLASS_STAGING","FAULT_CLASS_UNSUPPORTED_FEATURE"};

        TimeStep ts = new TimeStep (stepStr, n, inputDate);     
        System.out.println("<report>");
        
        
        DatabaseRetriever dbr = new DatabaseRetriever();
        
        HistogramParser gt2hist = new HistogramParser("Breakdown of GT2 Codes", "gt2histogram", "Jobs with Each Error code", n);
        
        HistogramParser faulthist = new HistogramParser("Breakdown of Fault Classes", "faulthistogram", "Number of Jobs with Fault Class", n);

        while(ts.next()){
            Date startTime = ts.getTime();
            String startDate = ts.getFormattedTime();
            ts.stepTime();

            gt2hist.nextEntry(startDate, ts.getFormattedTime());
            faulthist.nextEntry(startDate, ts.getFormattedTime());

            int totalJobs = 0;
            int gt2Jobs = 0;
            int faultJobs = 0;

            ResultSet rs = dbr.retrieve(new String ("gram_packets"), new String [] {"gt2_error_code","fault_class"}, startTime, ts.getTime());
            while (rs.next()){
                totalJobs++;
                if (rs.getInt(1) != 0){
                    gt2Jobs++;
                    gt2hist.addData(rs.getString(1), 1);
                }
                if (rs.getInt(2) != 0){
                    faultJobs++;
                    faulthist.addData(faultNames[rs.getInt(2)], 1);
                }


            }
            rs.close();

                System.out.println(" <entry>");
                System.out.println("\t<start-date>" + startDate + "</start-date>");
                System.out.println("\t<end-date>" + ts.getFormattedTime() + "</end-date>");
                System.out.println("\t<total-jobs>"+totalJobs+"</total-jobs>");
               
                System.out.println("\t<jobs-with-error-code>"+f.format(100.0*gt2Jobs/totalJobs)+"</jobs-with-error-code>");

                System.out.println("\t<jobs-with-fault>"+f.format(100.0*faultJobs/totalJobs)+"</jobs-with-fault>");

                System.out.println(" </entry>");            
        }
        dbr.close();
        gt2hist.output(System.out);
        faulthist.output(System.out);
        System.out.println("</report>");
    }
}
