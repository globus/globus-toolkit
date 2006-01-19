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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.exec.generated.StateEnumeration;
import org.globus.exec.monitoring.AlreadyRegisteredException;
import org.globus.exec.monitoring.JobStateChangeListener;
import org.globus.exec.monitoring.JobStateMonitor;
import org.globus.exec.monitoring.JobStateRecoveryListener;
import org.globus.exec.monitoring.NotRegisteredException;
import org.globus.exec.monitoring.SchedulerEvent;

import org.globus.wsrf.ResourceKey;

/**
 * The SchedulerEventGeneratorMonitor (JSM) is a scheduler-indpendent object which provides
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

public class SchedulerEventGeneratorMonitor implements JobStateMonitor
{
    private static Log logger = LogFactory.getLog(SchedulerEventGeneratorMonitor.class);

    /** Reference to the SEG-monitoring thread. */
    private SchedulerEventGenerator seg;
    /**
     * JobStateChangeListener which will be notified of job state
     * changes for registered job IDs.
     */
    private JobStateChangeListener listener;
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
     * the persistent state of the SchedulerEventGeneratorMonitor.
     */
    private java.util.TimerTask recoveryTask;

    /**
     * Timestamp of the last dispatched event.
     *
     * This timestamp is used as the safe-recovery timestamp when the
     * soft-state event cache is empty, but some events have been dispatched
     * to their JobStateChangeListener or discarded from the soft-state cache
     * by the cacheFlushTask.
     */
    private java.util.Date lastEventTimestamp;

    /**
     * Construct a new SchedulerEventGeneratorMonitor with a non-daemon SEG.
     *
     * The new SchedulerEventGeneratorMonitor will not begin the Scheduler Event Generator
     * automatically.  Services which create a SchedulerEventGeneratorMonitor may register
     * any number of job ID mappings before calling start() to start
     * the SEG.
     *
     * @param segPath
     *     Path to the SEG executable.
     * @param userName
     *     User name that the SEG should run as (via sudo(8)).
     *     (Currently ignored).
     * @param schedulerName
     *     Name of the scheduler SEG module to use.
     * @param listener
     *     Reference to the JobStateChangeListener which will be notified
     *     when notifications relating to Job ID which has a mapping
     *     registered to it.
     * @param recoveryListener
     *     Reference to a JobStateRecoveryListener which will be notified
     *     periodically when the SchedulerEventGeneratorMonitor wants to update its recovery
     *     checkpoint timestamp.
     */
    public SchedulerEventGeneratorMonitor(
        java.io.File                        segPath,
        String                              userName,
        String                              schedulerName,
        JobStateChangeListener              listener,
        JobStateRecoveryListener            recoveryListener)
    {
        this(segPath,
             userName,
             schedulerName,
             listener,
             recoveryListener,
             false);
    }

    /**
     * Construct a new SchedulerEventGeneratorMonitor.
     *
     * The new SchedulerEventGeneratorMonitor will not begin the Scheduler Event Generator
     * automatically.  Services which create a SchedulerEventGeneratorMonitor may register
     * any number of job ID mappings before calling start() to start
     * the SEG.
     *
     * @param segPath
     *     Path to the SEG executable.
     * @param userName
     *     User name that the SEG should run as (via sudo(8)).
     *     (Currently ignored).
     * @param schedulerName
     *     Name of the scheduler SEG module to use.
     * @param listener
     *     Reference to the JobStateChangeListener which will be notified
     *     when notifications relating to Job ID which has a mapping
     *     registered to it.
     * @param recoveryListener
     *     Reference to a JobStateRecoveryListener which will be notified
     *     periodically when the SchedulerEventGeneratorMonitor wants to update its recovery
     *     checkpoint timestamp.
     * @param segDaemon
     *     Indicates whether to make the SEG a daemon thread or not
     */
    public SchedulerEventGeneratorMonitor(
        java.io.File                        segPath,
        String                              userName,
        String                              schedulerName,
        JobStateChangeListener              listener,
        JobStateRecoveryListener            recoveryListener,
        boolean                             segDaemon)
    {
        logger.debug("Constructing SchedulerEventGeneratorMonitor");

        this.listener = listener;
        this.recoveryListener = recoveryListener;
        this.mapping = new java.util.HashMap();
        this.cachedEvents
            = new java.util.TreeSet(SchedulerEvent.getComparator());
        this.cacheFlushTask = null;
        this.recoveryTask = null;

        this.seg = new SchedulerEventGenerator(
            segPath,
            userName,
            schedulerName,
            this);
        logger.debug("Setting SEG daemon status to " + segDaemon);
        this.seg.setDaemon(segDaemon);
    }

    /**
     * Register a mapping from local scheduler job ID to a resource key.
     *
     * Once this method has been called for a particular local job
     * identifier, the JobStateChangeListener associated with the
     * JobStatemonitor may receive notifications until the unregisterJobIDMap
     * method has been called.
     *
     * @param localId
     *     Local job identifier. This is presumably generated by the
     *     scheduler when the job is created.
     * @param resourceKey
     *     Resource key associated with the job. This object will be
     *     passed to the JobStateChangeListener's jobStateChange method.
     */
    public synchronized void registerJobID(String localId, ResourceKey resourceKey)
            throws AlreadyRegisteredException
    {
        if (logger.isDebugEnabled()) {
            logger.debug("Entering registerJobID: " + localId);
        }
        synchronized (mapping) {
            if (mapping.containsKey(localId)) {
                throw new AlreadyRegisteredException(localId);
            }
            mapping.put(localId, resourceKey);

            java.util.List events = getCachedEvents(localId);

            if (events != null) {
                DispatcherThread t = new DispatcherThread(resourceKey,
                        events);
                t.start();
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
     * the SchedulerEventGeneratorMonitor.
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

        if (logger.isDebugEnabled()) {
            logger.debug("starting seg with timestamp " + timestamp.toString());
        }

        this.seg.start(timestamp);
        this.lastEventTimestamp = timestamp;

        if (cacheFlushTask == null) {
            logger.debug("creating flush task");
            cacheFlushTask = new java.util.TimerTask() {
                public void run() {
                    flushCache();
                }
            };

            timer.schedule(cacheFlushTask, CACHE_FLUSH_PERIOD,
                    CACHE_FLUSH_PERIOD);
        }

        if (recoveryTask == null && recoveryListener != null) {
            logger.debug("creating recovery update task");
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
                logger.debug("joining SEG thread");
                seg.join();
                logger.debug("done");
                done = true;
            } catch (InterruptedException ie) {
            }
        }
        logger.debug("Exiting stop()");
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
                d = ((SchedulerEvent) i.next()).getTimeStamp();

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
     * @return Returns a list of SchedulerEvents associated with the Job ID.
     */
    private java.util.List getCachedEvents(String localId)
    {
        logger.debug("Entering getCachedEvents()");
        java.util.List result = new java.util.ArrayList(4);

        synchronized (cachedEvents) {
            java.util.Iterator i = cachedEvents.iterator();

            while (i.hasNext()) {
                SchedulerEvent e = (SchedulerEvent) i.next();

                if (e.getLocalId().equals(localId)) {
                    logger.debug("adding " + e.toString()
                            + "to list to replay");
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
     * identifier, the JobStateChangeListener associated with the
     * JobStatemonitor will no longer receive notifications about this job.
     *
     * @param localId
     *     Local job identifier.
     */
    public void unregisterJobID(String localId)
        throws NotRegisteredException
    {
        if (logger.isDebugEnabled()) {
            logger.debug("Entering unregisterJobID: " + localId);
        }

        synchronized (mapping) {
            Object result = mapping.remove(localId);

            if (result == null) {
                throw new NotRegisteredException(localId);
            }
        }
        logger.debug("Exiting unregisterJobID()");
    }

    /**
     * Store an event in the SchedulerEventGeneratorMonitor's cache
     */
    private void cacheEvent(SchedulerEvent e)
    {
        logger.debug("Entering cacheEvent()");
        synchronized (cachedEvents) {
            logger.debug("caching " + e.toString());
            cachedEvents.add(e);
        }
        logger.debug("Exiting cacheEvent()");
    }

    /**
     * Look up the localId to ResourceKey mapping for a specified id.
     */
    private ResourceKey getMapping(String localId)
    {
        synchronized (mapping) {
            return (ResourceKey) mapping.get(localId);
        }
    }

    public synchronized void addEvent(SchedulerEvent e) {
        if (logger.isDebugEnabled()) {
            logger.debug(" JSM receiving scheduler event " + e);
        }
        String localId = e.getLocalId();

        ResourceKey mapping = getMapping(localId);

        if (mapping != null) {
            logger.debug("Dispatching event " + e.getLocalId()
                        + " to job " + mapping.getValue());

            dispatchEvent(mapping, e);
        } else {
            logger.debug("Caching event " + e.getLocalId());

	    cacheEvent(e);
        }
    }

    /**
     * Call the jobStateChange callback for a SEG event.
     *
     * @param resourceKey
     *     Resource key associated with the job ID in the event.
     * @param e
     *     Event containing the job state change information.
     */
    void dispatchEvent(ResourceKey resourceKey, SchedulerEvent e)
    {
        logger.debug("Entering dispatchEvent()");

        synchronized (mapping) {
            logger.debug("dispatching " + e.toString());
            listener.jobStateChanged(resourceKey, e.getLocalId(),
                    e.getTimeStamp(), e.getState(), e.getExitCode());

            synchronized (cachedEvents) {
                /* If called from a DispatcherThread, the event may
                 * be in the cache. If so, when we remove it the cached
                 * may be empty
                 */
                if (cachedEvents.remove(e) && cachedEvents.isEmpty()) {
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

    private class DispatcherThread extends Thread {
        private ResourceKey resourceKey;
        private java.util.List events;

        public DispatcherThread(ResourceKey resourceKey,
                java.util.List events)
        {
            super();

            this.resourceKey = resourceKey;
            this.events = events;
        }

        public void run() {
            java.util.Iterator i = events.iterator();

            while (i.hasNext()) {
                SchedulerEvent e = (SchedulerEvent) i.next();

                dispatchEvent(resourceKey, e);
            }
        }
    }
}
