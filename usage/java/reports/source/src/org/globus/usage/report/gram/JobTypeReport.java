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

import java.util.HashMap;
import java.util.Map;
import java.util.Iterator;
import java.util.Date;
import java.util.Locale;

public class JobTypeReport{
    
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

        DatabaseRetriever dbr = new DatabaseRetriever();

        TimeStep ts = new TimeStep (stepStr, n, inputDate);     

        System.out.println("<job-type-report>");

        int totalJobs;
        int singleJobs;
        int MPIJobs;
        int condorJobs;
        int multipleJobs;

        while(ts.next()){
            totalJobs=0;
            singleJobs = 0;
            MPIJobs = 0;
            condorJobs = 0;
            multipleJobs = 0;

            String startDate = ts.getFormattedTime();

            ResultSet rs = dbr.retrieve(new String ("gram_packets"), new String [] {"job_type"}, ts.getTime(), ts.stepTime());
            while (rs.next()){
                totalJobs++;
                int type = rs.getInt(1);
                if (type == 0 || type==2) {multipleJobs++;}
                else if (type == 1) {singleJobs++;}
                else if (type == 3) {MPIJobs++;}
                else if (type == 4) {condorJobs++;}
            }
            rs.close();

                System.out.println(" <entry>");
                System.out.println("\t<start-date>" + startDate + "</start-date>");
                System.out.println("\t<end-date>" + ts.getFormattedTime() + "</end-date>");

                System.out.println("\t<job-types>");
                System.out.println("\t\t<single-jobs>"+f.format(100.0*singleJobs/totalJobs)+"</single-jobs>");
                System.out.println("\t\t<multiple-jobs>"+f.format(100.0*multipleJobs/totalJobs)+"</multiple-jobs>");
                System.out.println("\t\t<condor-jobs>"+f.format(100.0*condorJobs/totalJobs)+"</condor-jobs>");
                System.out.println("\t\t<MPI-jobs>"+f.format(100.0*MPIJobs/totalJobs)+"</MPI-jobs>");
                System.out.println("\t</job-types>");

                System.out.println(" </entry>");
            
        }
        dbr.close();
        System.out.println("</job-type-report>");
    }
}
