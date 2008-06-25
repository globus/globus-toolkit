/*
 * Copyright 1999-2008 University of Chicago
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

package org.globus.usage.receiver;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.zip.GZIPInputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.CustomByteBuffer;

public class LogParser {
    private static Log log = LogFactory.getLog(LogParser.class);
    private final static int RING_BUFFER_SIZE = 1024;

    private RingBufferFile ring;
    
    public LogParser(File outputDir, int size) throws IOException {
        ring = new RingBufferFile(size, outputDir, false);
    }

    public LogParser(File outputDir) throws IOException {
        this(outputDir, RING_BUFFER_SIZE);
    }

    public void processLogStream(InputStream is)
    throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));

        String line;
        while ((line = reader.readLine()) != null) {
            String [] logLineData = line.split(" ", 6);

            if (logLineData.length == 6 &&
                logLineData[2].equals("ERROR") &&
                logLineData[3].equals("handlers.DefaultPacketHandler")) {
                String packet = logLineData[5];

                if (Character.isDigit(packet.charAt(0))) {
                    byte [] data;
                    String [] digits = logLineData[5].split(", ");
                    data = new byte[digits.length];

                    for (int i = 0; i < digits.length; i++) {
                        data[i] = Byte.parseByte(digits[i]);
                    }
                    CustomByteBuffer buffer =
                        CustomByteBuffer.fitToData(data, data.length);
                    ring.insert(buffer);
                }
            }
        }
        ring.flush();
    }


    public void processLog(File f)
    throws IOException {
        if (f.isDirectory()) {
            processLogDirectory(f);
        } else {
            processLogFile(f);
        }
    }

    public void processLogDirectory(File dir) throws IOException {
        String [] logs = dir.list(new FilenameFilter() {
            public boolean accept(File dir, String name) {
                return (name.startsWith("receiver.log"));
            }});

        for (int i = 0; i < logs.length; i++) {
            File log = new File(dir, logs[i]);

            processLogFile(log);
        }
    }

    public void processLogFile(File f) throws IOException {
        InputStream is;

        is = new FileInputStream(f);

        if (f.toString().endsWith(".gz")) {
            is = new GZIPInputStream(is);
        }

        processLogStream(is);
    }

    public static void main(String args[]) throws IOException {
        String USAGE = "org.globus.usage.receiver.LogParser [-help]\n" +
                       "[-l log-directory] [-o output-directory]";
        String logDirectory = ".";
        String outputDirectory = ".";

        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-h") || args[i].equals("-help")) {
                System.out.println(USAGE);
                System.exit(0);
            } else if (args[i].equals("-l") && ++i < args.length) {
                logDirectory = args[i];
            } else if (args[i].equals("-o") && ++i < args.length) {
                outputDirectory = args[i];
            } else {
                System.err.println("Unknown parameter " + 
                    ((i == args.length) ? args[i-1] : args[i]));
                System.exit(1);
            }
        }

        LogParser lp = new LogParser(new File(outputDirectory));

        lp.processLog(new File(logDirectory));
    }
}
