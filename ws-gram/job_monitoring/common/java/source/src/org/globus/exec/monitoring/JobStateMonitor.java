package org.globus.exec.monitoring;

/**
 * The JobStateMonitor (JSM) is a scheduler-indpendent object which provides
 * notifications of job state changes to the Managed Job Service (MJS).
 *
 * <p>
 * It provides an interface between the process monitoring of the Scheduler
 * Event Generator (SEG) and the Managed Job Resources which contain the
 * state of a job created by the ManagedJobService (MJS).
 * </p>
 * <p>
 * The JSM contains a registry mapping scheduler-specific job identifiers to
 * Object keys which the MJS can use to map job state changes to particular
 * job resources.
 * </p>
 * <p>
 * The JSM also contains a soft-state cache of SEG events which aren't
 * yet associated with MJR keys in its registry. Events in this cache are
 * replayed if and when the MJS creates an association between a local Job
 * ID and an Object key. Events which aren't used for some 
 * interval are automatically discarded by the JSM.
 * </p>
 * <p>
 * The JSM also provides a persistent state callback to periodically update
 * the persistent state information. If this information is passed back to
 * the start() method of the JSM, it will be able to resume processing
 * from where its last event and not lose any events. Some events may be
 * repeated when restarts are done, and the user of this class must be
 * prepared to handle that.
 * </p>
 */

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class JobStateMonitor {
    private static Log logger = LogFactory.getLog(JobStateMonitor.class);

    /** Reference to the runtime used to start the SEG process */
    private static Runtime runtime = Runtime.getRuntime();
    /** Reference to the SEG-monitoring thread. */
    private Seg seg;
    /**
     * JobStateListener which will be notified of job state
     * changes for registered job IDs.
     */
    private JobStateListener listener;
    /**
     * JobStateRecoveryListener which will be notified when the JSM decides
     * that its recovery information should be updated.
     */
    private JobStateRecoveryListener recoveryListener;
    /** Mapping of Job IDs to Object keys */
    private java.util.HashMap mapping;
    /** Time-sorted soft-state cache of events */
    private java.util.SortedSet cachedEvents;
    /**
     * Maximum age of the oldest event in the soft-state cache.
     */
    private static final int MAX_CACHE_AGE = 5 * 60 * 1000;
    /**
     * Period of time between running the cache flush task.
     */
    private static final long CACHE_FLUSH_PERIOD = 1 * 60 * 1000;
    /**
     * Period of time between running the recovery update task.
     */
    private static final long RECOVERY_PERIOD = 15 * 60 * 1000;
    /**
     * Timer to handle all cache flushing and recovery timestamp update tasks.
     */
    private static java.util.Timer timer = new java.util.Timer(true);
    /**
     * Cache flushing task.
     *
     * Every CACHE_FLUSH_PERIOD milliseconds, cache entries older than
     * MAX_CACHE_AGE will be discarded.
     */
    private java.util.TimerTask cacheFlushTask;
    /**
     * Recovery data update task.
     *
     * Every RECOVERY_PERIOD milliseconds, recoveryListener's
     * updateJobMonitorRecoveryTimeStamp() will be called to have it update
     * the persistent state of the JobStateMonitor.
     */
    private java.util.TimerTask recoveryTask;

    /**
     * Timestamp of the last dispatched event.
     *
     * This timestamp is used as the safe-recovery timestamp when the
     * soft-state event cache is empty, but some events have been dispatched
     * to their JobStateListener or discarded from the soft-state cache by
     * the cacheFlushTask.
     */
    private java.util.Date lastEventTimestamp;

    /**
     * Construct a new JobStateMonitor.
     *
     * The new JobStateMonitor will not begin the Scheduler Event Generator
     * automatically.  Services which create a JobStateMonitor may register
     * any number of job ID mappings before calling start() to start
     * the SEG.
     *
     * @param segPath
     *     Path to the SEG executable.
     * @param userName
     *     User name that the SEG should run as (via sudo(8)).
     *     (Currently ignored).
     * @param schedulerPath
     *     Path to the scheduler-specific SEG module.
     * @param listener
     *     Reference to the JobStateListener which will be notified
     *     when notifications relating to Job ID which has a mapping
     *     registered to it.
     * @param recoveryListener
     *     Reference to a JobStateRecoveryListener which will be notified
     *     periodically when the JobStateMonitor wants to update its recovery
     *     checkpoint timestamp.
     */
    public JobStateMonitor(
            java.io.File segPath,
            String userName,
            java.io.File schedulerPath,
            JobStateListener listener,
            JobStateRecoveryListener recoveryListener)
    {
        logger.debug("Constructing JobStateMonitor");

        this.listener = listener;
        this.recoveryListener = recoveryListener;
        this.mapping = new java.util.HashMap();
        this.cachedEvents = new java.util.TreeSet(SegEvent.getComparator());
        this.cacheFlushTask = null;
        this.recoveryTask = null;

        this.seg = new Seg(segPath, userName, schedulerPath); 
    }

    /**
     * Register a mapping from local scheduler job ID to a resource key.
     *
     * Once this method has been called for a particular local job
     * identifier, the JobStateListener associated with the
     * JobStatemonitor may receive notifications until the unregisterJobIDMap
     * method has been called.
     *
     * @param localId
     *     Local job identifier. This is presumably generated by the
     *     scheduler when the job is created.
     * @param resourceKey
     *     Resource key associated with the job. This object will be
     *     passed to the JobStateListener's jobStateChange method.
     */
    public void registerJobID(String localId, Object resourceKey)
            throws AlreadyRegisteredException
    {
        logger.debug("Entering registerJobID");
        synchronized (mapping) {
            if (mapping.containsKey(localId)) {
                throw new AlreadyRegisteredException(localId);
            }
            mapping.put(localId, resourceKey);

            java.util.List events = getCachedEvents(localId);

            if (events != null) {
                SegEvent e;

                java.util.Iterator eventIt = events.iterator();

                while (eventIt.hasNext()) {
                    e = (SegEvent) eventIt.next();

                    logger.debug("Replaying event: " + e);

                    dispatchEvent(resourceKey, e);
                }
            }
        }
        logger.debug("Exiting registerJobID");
    }

    /**
     * Start processing SEG events.
     *
     * Starts the SEG thread processing events from the scheduler, as
     * well as some background tasks to flush cache of old job
     * events and to update the persistent timestamp used for restarting
     * the JobStateMonitor.
     * 
     *
     * @param timestamp 
     *     Date from which to start processing events. If <b>null</b>, then
     *     the SEG will process events generated from the time the function
     *     is called.
     * @throws IllegalThreadStateException
     *     This method has already been called.
     */
    public void start(java.util.Date timestamp)
            throws IllegalThreadStateException
    {
        logger.debug("Entering start()");

        if (timestamp == null) {
            timestamp = new java.util.Date();
        }

        seg.start(timestamp);
        lastEventTimestamp = timestamp;

        if (cacheFlushTask == null) {
            cacheFlushTask = new java.util.TimerTask() {
                public void run() {
                    flushCache();
                }
            };

            timer.schedule(cacheFlushTask, CACHE_FLUSH_PERIOD,
                    CACHE_FLUSH_PERIOD);
        }

        if (recoveryTask == null && recoveryListener != null) {
            recoveryTask = new java.util.TimerTask() {
                public void run() {
                    updateRecoveryInfo();
                }
            };

            timer.schedule(recoveryTask, RECOVERY_PERIOD, RECOVERY_PERIOD);
        }
        logger.debug("Exiting start()");
    }

    /** 
     * Stop processing SEG events.
     *
     * Blocks the current thread until the SEG has terminated. No furthur
     * SEG events will be issued after method returns until the start() method
     * is called again.
     */
    public void stop()
            throws java.io.IOException
    {
        logger.debug("Entering stop()");

        boolean done = false;

        seg.shutdown();

        while (!done) {
            try {
                seg.join();
                done = true;
            } catch (InterruptedException ie) {
            }
        }
        logger.debug("Exiting stop()");
    }

    /**
     * Call the jobStateChange callback for a SEG event.
     *
     * @param resourceKey
     *     Object key associated with the job ID in the event.
     * @param e
     *     Event containing the job state change information.
     */
    private void dispatchEvent(Object resourceKey, SegEvent e)
    {
        logger.debug("Entering dispatchEvent()");

        synchronized (mapping) {
            logger.debug("dispatching " + e.toString());
            listener.jobStateChange(resourceKey, e.getTimeStamp(),
                    e.getState(), e.getExitCode());
            synchronized (cachedEvents) {
                if (cachedEvents.isEmpty()) {
                    if (recoveryTask != null) {
                        synchronized (recoveryTask) {
                            lastEventTimestamp = e.getTimeStamp();
                        }
                    }
                }
            }
        }
        logger.debug("Exiting dispatchEvent()");
    }

    private void cacheEvent(SegEvent e)
    {
        logger.debug("Entering cacheEvent()");
        synchronized (cachedEvents) {
            logger.debug("caching " + e.toString());
            cachedEvents.add(e);
        }
        logger.debug("Exiting cacheEvent()");
    }

    private void flushCache()
    {
        logger.debug("Entering flushCache()");

        java.util.Calendar flushCalendar = java.util.Calendar.getInstance();

        flushCalendar.add(java.util.Calendar.MILLISECOND, -MAX_CACHE_AGE);

        java.util.Date flushDate = flushCalendar.getTime();

        synchronized (cachedEvents) {
            java.util.Iterator i = cachedEvents.iterator();
            java.util.Date d = null;

            while (i.hasNext()) {
                d = ((SegEvent) i.next()).getTimeStamp();

                if (d.compareTo(flushDate) <= 0) {
                    /* Remove older than MAX_CACHE_AGE */
                    i.remove();
                } else {
                    /* Sorted, so we don't need to continue once we find
                     * a non-old timestamp
                     */
                    break;
                }
            }

            if (d != null)
            {
                if (d.compareTo(lastEventTimestamp) > 0) {
                    /* Newer than the oldest safe recovery point, so we'll
                     * update that date
                     */
                    if (recoveryTask != null) {
                        synchronized (recoveryTask) {
                            lastEventTimestamp = d;
                        }
                    }
                }
            }
        }
        logger.debug("Exiting flushCache()");
    }

    private void updateRecoveryInfo()
    {
        logger.debug("Entering updateRecoveryInfo()");

        java.util.Date d;

        synchronized (recoveryTask) {
            d = lastEventTimestamp;
        }

        recoveryListener.updateJobMonitorRecoveryTimeStamp(this, d);
        logger.debug("Exiting updateRecoveryInfo()");
    }

    /**
     * Get all cached events associated with a Job ID.
     *
     * @param localId
     *     Job identifier to look up.
     *
     * @return Returns a list of SegEvents associated with the Job ID.
     */
    private java.util.List getCachedEvents(String localId)
    {
        logger.debug("Entering getCachedEvents()");
        java.util.List result = new java.util.ArrayList(4);

        synchronized (cachedEvents) {
            java.util.Iterator i = cachedEvents.iterator();

            while (i.hasNext()) {
                SegEvent e = (SegEvent) i.next();

                if (e.getLocalId().equals(localId)) {
                    i.remove();

                    result.add(e);
                }
            }
        }
        logger.debug("Exiting getCachedEvents()");
        return result;
    }

    /**
     * Unregister a local scheduler job ID for event propagation.
     * Once this method has been called for a particular local job
     * identifier, the JobStateListener associated with the
     * JobStatemonitor will no longer receive notifications about this job.
     *
     * @param localId
     *     Local job identifier.
     */
    public void unregisterJobID(String localId)
        throws NotRegisteredException
    {
        logger.debug("Entering unregisterJobID()");

        synchronized (mapping) {
            Object result = mapping.remove(localId);

            if (result == null) {
                throw new NotRegisteredException(localId);
            }
        }
        logger.debug("Exiting unregisterJobID()");
    }

    /**
     * Scheduler Event Generator monitor thread.
     * 
     * The Seg object creates a Scheduler Event Generator process to 
     * monitor job state changes associated with a particular scheduler.
     *
     * The Seg object will repeatedly start the SEG process if it terminates
     * prematurely, until its shutdown() method is called.
     */
    private class Seg extends Thread {
        /** Path to the SEG executable */
        private java.io.File path;
        /**
         * Username of the account to run the SEG as.
         *
         * <b>This is currently ignored.</b>
         */
        private String userName;
        /** Path to the SEG executable */
        private java.io.File schedulerPath;
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
         * SEG constructor.
         *
         * @param path
         *     Path to the Scheduler Event Generator executable.
         * @param userName
         *     Username to sudo(8) to start the SEG.
         * @param schedulerPath
         *     schedulerPath
         */
        public Seg(java.io.File path, String userName,
                java.io.File schedulerPath) 
        {
            this.path = path;
            this.userName = userName;
            this.schedulerPath = schedulerPath;
            this.proc = null;
            this.shutdownCalled = false;
            this.timeStamp = null;
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

                    stdout = new java.io.BufferedReader(
                            new java.io.InputStreamReader(
                                    proc.getInputStream()));
                    while ((input = stdout.readLine()) != null) {
                        java.util.StringTokenizer tok =
                                new java.util.StringTokenizer(input, ";");
                        int tokenCount = tok.countTokens();
                        String tokens[] = new String[tok.countTokens()];

                        for (int i = 0; i < tokens.length; i++) {
                            tokens[i] = tok.nextToken();
                        }

                        if (tokens[0].equals("001")) {
                            // Job state change message
                            if (tokens.length < 5) {
                                // Invalid message
                            }

                            SegEvent e = new SegEvent(
                                new java.util.Date(
                                    Long.parseLong(tokens[1])*1000),
                                tokens[2],
                                Integer.parseInt(tokens[3]),
                                Integer.parseInt(tokens[4]));

                            timeStamp = e.getTimeStamp();

                            synchronized (mapping) {
                                Object resourceKey = mapping.get(tokens[2]);

                                if (resourceKey != null) {
                                    dispatchEvent(resourceKey, e);
                                } else {
                                    cacheEvent(e);
                                }
                            }
                        } else {
                            // Unknown message type
                        }
                    }
                }
            } catch (java.io.IOException ioe) {
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
        private synchronized boolean startSegProcess(java.util.Date timeStamp)
                throws java.io.IOException
        {
            proc = null;

            if (!shutdownCalled) {
                String [] cmd;

                // TODO: sudo integration here
                if (timeStamp != null) {
                    cmd = new String[] {
                        path.toString(),
                        "-s", schedulerPath.toString(),
                        "-t", Long.toString(
                                timeStamp.getTime() / 1000)};
                } else {
                    cmd = new String[] {
                        path.toString(), "-s", schedulerPath.toString()
                    };
                }
                proc = runtime.exec(cmd);
                return true;
            } else {
                return false;
            }
        }

        /**
         * Tell a SEG process to terminate.
         * 
         * This function closes the standard input of the SEG process started
         * by this object and will cause the thread associated with this
         * object to terminate once all input has been processed.
         */
        public synchronized void shutdown()
                throws java.io.IOException
        {
            if (shutdownCalled) {
                return;
            } else {
                if (proc != null) {
                    proc.getOutputStream().close();
                }
                shutdownCalled = true;
            }
        }
        
        public void start(java.util.Date timeStamp) {
            this.timeStamp = timeStamp;

            start();
        }
    }
}
