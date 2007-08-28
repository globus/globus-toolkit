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
package org.globus.exec.monitoring.seg;

import java.io.File;
import java.io.IOException;
import java.util.Date;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.globus.exec.generated.StateEnumeration;
import org.globus.exec.monitoring.JobStateMonitor;
import org.globus.exec.monitoring.SchedulerEvent;

/**
 * Scheduler Event Generator monitor thread.
 * 
 * The Seg object creates a Scheduler Event Generator process to 
 * monitor job state changes associated with a particular scheduler.
 *
 * The Seg object will repeatedly start the SEG process if it terminates
 * prematurely, until its shutdown() method is called.
 */
class SchedulerEventGenerator extends Thread {
    private static Log logger =
            LogFactory.getLog(SchedulerEventGenerator.class);

    /** Reference to the runtime used to start the SEG process */
    private static Runtime runtime = Runtime.getRuntime();

    private static final String SEG_EXECUTABLE_NAME = 
    	"globus-scheduler-event-generator";
    
    /** Path to the SEG executable */
    private File path;
    /**
     * Username of the account to run the SEG as.
     * <b>This is currently ignored.</b>
     */
    private String userName;
    /** Path to the SEG executable */
    private String schedulerName;
    /** SEG Process handle */
    private Process proc;
    /**
     * Flag indicating that the SEG process should no longer be
     * restarted and the thread should terminate.
     */
    private boolean shutdownCalled;
    /**
     * Timestamp of last event we've received from a SEG.
     */
    private java.util.Date timeStamp;

    /**
     * Monitor which created this SchedulerEventGenerator.
     * We call its addEvent() method when a new event is read from the
     * SEG process.
     */
    private JobStateMonitor monitor;

    /**
     * Used to keep track of the last restart time for the SEG process---if
     * it was too recent (less than our THROTTLE_RESTART_THRESHOLD) wait 
     * THROTTLE_RESTART_TIME before trying again.
     */
    private long lastRestart = 0;
    /**
     * When throttling process restarts, wait this many milliseconds before
     * next restart attempt.
     */
    private final long THROTTLE_RESTART_TIME = 2 * 60 * 1000;
    /**
     * When SEG terminates within this amount of time of being started, assume
     * something might be wrong and delay again.
     */
    private final long THROTTLE_RESTART_THRESHOLD = 2 * 1000;
    /**
     * SEG constructor.
     *
     * @param path
     *     Path to the Scheduler Event Generator executable.
     * @param userName
     *     Username to sudo(8) to start the SEG.
     * @param schedulerName
     *     Name of the scheduler SEG module to use (fork, lsf, etc).
     * @param monitor
     *     JobStateMonitor that will be notified if and Event comes in
     * @param segDaemon
     *     Indicates whether the SEG should be started as daemon or not
     */
    public SchedulerEventGenerator(
        String                              globusLocation,
        String                              userName,
        String                              schedulerName,
        JobStateMonitor                     monitor,
        boolean                             segDaemon) 
    {
        this.userName = userName;
        this.schedulerName = schedulerName;
        this.proc = null;
        this.shutdownCalled = false;
        this.timeStamp = null;
        this.monitor = monitor;
        this.setDaemon(segDaemon);
        this.path = new File(globusLocation +
                File.separator + "libexec" +
                File.separator + SEG_EXECUTABLE_NAME);
        lastRestart = 0;
    }
    

    /**
     * Start and monitor a SEG process.
     *
     * When the SEG terminates by itself for whatever reason, this thread
     * will restart it using the timestamp of the last item which was in
     * the event cache.
     */
    public void run() {
        try {
            while (startSegProcess(timeStamp)) {
                java.io.BufferedReader stdout;
                String input; 

                logger.debug("getting seg input");
                stdout = new java.io.BufferedReader(
                        new java.io.InputStreamReader(
                                proc.getInputStream()));
                if (logger.isDebugEnabled()) {
                    logger.debug("Seg input buffer is "
                    + (stdout.ready()?"read":"not ready"));
                    try
                    {
                        int rc = proc.exitValue();
                        logger.error("SEG terminated with return code " + rc);
                    }
                    catch (IllegalThreadStateException itse)
                    {
                        logger.debug("SEG still running...");
                    }
                }
                while ((input = stdout.readLine()) != null) {
                    logger.debug("seg input line: " + input);
                    java.util.StringTokenizer tok =
                            new java.util.StringTokenizer(input, ";");
                    String tokens[] = new String[tok.countTokens()];

                    for (int i = 0; i < tokens.length; i++) {
                        tokens[i] = tok.nextToken();
                    }

                    if (tokens[0].equals("001")) {
                        // Job state change message
                        if (tokens.length < 5) {
                            // Invalid message
                        }

                        StateEnumeration se;

                        switch (Integer.parseInt(tokens[3])) {
                            case 1:
                                se = StateEnumeration.Pending;
                                break;
                            case 2:
                                se = StateEnumeration.Active;
                                break;
                            case 4:
                                se = StateEnumeration.Failed;
                                break;
                            case 8:
                                se = StateEnumeration.Done;
                                break;
                            case 16:
                                se = StateEnumeration.Suspended;
                                break;
                            case 32:
                                se = StateEnumeration.Unsubmitted;
                                break;
                            default:
                                se = null;
                        }

                        SchedulerEvent e = new SchedulerEvent(
                            new java.util.Date(
                                Long.parseLong(tokens[1])*1000),
                            tokens[2],
                            se,
                            Integer.parseInt(tokens[4]));

                        timeStamp = e.getTimeStamp();

                        monitor.addEvent(e);
                    } else {
                        // Unknown message type
                    }
                }
                // if / when we get here, SEG has terminated, check stderr
                java.io.BufferedReader stderr;
                stderr = new java.io.BufferedReader(
                        new java.io.InputStreamReader(
                                proc.getErrorStream()));
                while ((input = stderr.readLine()) != null) {
                    logger.error("SEG Terminated with " + input);
                }
                stderr.close();

            }
        } catch (java.io.IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    /**
     * Start a scheduler event generator process.
     * 
     * This function is called to start a new scheduler event generator
     * process. This process will monitor the output of the scheduler
     * and send this object job state change notifications via the
     * processes's standard output stream.
     *
     * If the shutdown method of this object has been called, then the
     * process will not be started.
     *
     * @retval true New process started.
     * @reval false Did not create a new seg process.
     */
    private synchronized boolean startSegProcess(
        Date                                timeStamp)
        throws                              IOException
    {
        cleanProcess();

        proc = null;

        throttleRestart();

        if (!this.shutdownCalled) {
            logger.debug("Starting seg process");
            String [] cmd;

            // TODO: sudo integration here
            if (timeStamp != null) {
                cmd = new String[] {
                    this.path.toString(),
                    "-s", this.schedulerName,
                    "-t", Long.toString(
                            timeStamp.getTime() / 1000)};
            } else {
                cmd = new String[] {
                    this.path.toString(), "-s", this.schedulerName
                };
            }
            if (logger.isDebugEnabled()) {
                logger.debug("executing command: ");
                for (int i = 0; i  < cmd.length; i++) {
                    if (cmd[i] != null) {
                        logger.debug("->" + cmd[i]);
                    }
                }
            }
            proc = runtime.exec(cmd);
            logger.debug("seg exec returned");
            return true;
        } else {
            return false;
        }
    }

    /**
     * Delay THROTTLE_RESTART_TIME before returning unless either
     * <ul>
     * <li>The SEG process wasn't restarted within
     *    THROTTLE_RESTART_THRESHOLD</li>
     * <li>The shutdown method has been called</li>
     * </ul>
     */
    private synchronized void throttleRestart() {
        logger.debug("throttleRestart called");

        long thisTime = new java.util.Date().getTime();
        long endOfWait = thisTime + THROTTLE_RESTART_TIME;

        while ((!this.shutdownCalled) &&
                    ((thisTime - lastRestart) < THROTTLE_RESTART_THRESHOLD)) {
            logger.debug("Throttling the restart as we just restarted the SEG");
            try {
                wait(endOfWait - thisTime);
            } catch (InterruptedException ie) {
            }
            thisTime = new java.util.Date().getTime();
        }
        lastRestart = thisTime;
    }

    private synchronized void cleanProcess() {
        if (proc != null) {
            try { proc.getInputStream().close(); } catch (Exception e) {}
            try { proc.getOutputStream().close(); } catch (Exception e) {}
            try { proc.getErrorStream().close(); } catch (Exception e) {}
        }
    }

    /**
     * Tell a SEG process to terminate.
     * 
     * This function will cause the thread associated with this
     * object to terminate once all input has been processed.
     */
    public synchronized void shutdown()
            throws java.io.IOException
    {
        if (this.shutdownCalled) {
            return;
        } else {
            logger.debug("cleaning process");
            cleanProcess();
            logger.debug("setting shutdownCalled");
            this.shutdownCalled = true;
            /* Wake up throttler if we were waiting in it */
            logger.debug("notifying");
            notify();
            logger.debug("done");
        }
    }
    
    public void start(java.util.Date timeStamp) {
        logger.debug("Starting seg thread");
        this.timeStamp = timeStamp;

        start();
    }
}
