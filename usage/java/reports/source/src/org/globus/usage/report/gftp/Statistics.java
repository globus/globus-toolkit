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
import org.globus.usage.report.common.TimeStep;

import java.sql.ResultSet;

import java.text.NumberFormat;
import java.text.DecimalFormat;

import java.util.Date;
import java.util.Locale;

public class Statistics{
    
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
        
        DatabaseRetriever dbr = new DatabaseRetriever();

        long byteNumber;
        long packetNumber;
        double blocksize;
        double buffersize;

        System.out.println("<report>");

        while(ts.next()){
            byteNumber = 0;
            packetNumber=0;
            buffersize = 0;
            blocksize = 0;
            Date startD = ts.getTime();
            System.out.println("<entry>");
            System.out.println("<start-date>"+ts.getFormattedTime()+"</start-date>");
            String startS = ts.getFormattedTime();
            ts.stepTime();
            System.out.println("<end-date>"+ts.getFormattedTime()+"</end-date>");

            ResultSet rs = dbr.retrieve("gftp_packets", new String [] {"count(*)","sum(num_bytes)","sum(block_size)","sum(buffer_size)"}, startD, ts.getTime());
            rs.next();
            packetNumber+=rs.getLong(1);
            byteNumber+=rs.getLong(2);
            blocksize+=rs.getDouble(3);
            buffersize+=rs.getDouble(4);
  
            double bytemean= byteNumber/packetNumber;
            double blockmean = blocksize/packetNumber;
            double buffermean = buffersize/packetNumber;

            double bytedeviation = 0;
            double blockdeviation = 0;
            double bufferdeviation = 0;

            rs = dbr.retrieve("gftp_packets", new String[] {"num_bytes","block_size","buffer_size"}, startD, ts.getTime());
            while (rs.next()){
                bytedeviation = Math.pow(rs.getDouble(1) - bytemean, 2.0);
                blockdeviation = Math.pow(rs.getDouble(2) - blockmean, 2.0);
                bufferdeviation = Math.pow(rs.getDouble(3) - buffermean, 2.0);
            }

            bytedeviation = Math.pow(bytedeviation/packetNumber,.5);
            blockdeviation = Math.pow(blockdeviation/packetNumber,.5);
            bufferdeviation = Math.pow(bufferdeviation/packetNumber,.5);
        
            System.out.println("<byte>");
            System.out.println("\t<mean>"+f.format(bytemean)+"</mean>");
            System.out.println("\t<standard-deviation>"+f.format(bytedeviation)+"</standard-deviation>");
            System.out.println("\t<low-CI>"+f.format((bytemean-(1.96*bytedeviation)/Math.pow(packetNumber,.5)))+"</low-CI>");
            System.out.println("\t<high-CI>"+f.format((bytemean+(1.96*bytedeviation)/Math.pow(packetNumber,.5)))+"</high-CI>");
            System.out.println("</byte>");
           
            System.out.println("<block>");
            System.out.println("\t<mean>"+f.format(blockmean)+"</mean>");
            System.out.println("\t<standard-deviation>"+f.format(blockdeviation)+"</standard-deviation>");
            System.out.println("\t<low-CI>"+f.format((blockmean-(1.96*blockdeviation)/Math.pow(packetNumber,.5)))+"</low-CI>");
            System.out.println("\t<high-CI>"+f.format((blockmean+(1.96*blockdeviation)/Math.pow(packetNumber,.5)))+"</high-CI>");
            System.out.println("</block>");
           
            System.out.println("<buffer>");
            System.out.println("\t<mean>"+f.format(buffermean)+"</mean>");
            System.out.println("\t<standard-deviation>"+f.format(bufferdeviation)+"</standard-deviation>");
            System.out.println("\t<low-CI>"+f.format((buffermean-(1.96*bufferdeviation)/Math.pow(packetNumber,.5)))+"</low-CI>");
            System.out.println("\t<high-CI>"+f.format((buffermean+(1.96*bufferdeviation)/Math.pow(packetNumber,.5)))+"</high-CI>");
            System.out.println("</buffer>");

            System.out.println("</entry>");
            rs.close();     
        }
        dbr.close();
        System.out.println("</report>");
    }
}
