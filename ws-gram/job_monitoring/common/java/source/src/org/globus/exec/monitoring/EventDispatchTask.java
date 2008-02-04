/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */
package org.globus.exec.monitoring;

import org.globus.wsrf.ResourceKey;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.globus.exec.monitoring.seg.SchedulerEventGeneratorMonitor;

public class EventDispatchTask implements Runnable
{

    /** Log4J logger */
    private static Log logger = LogFactory.getLog(EventDispatchTask.class);
    private SchedulerEvent event = null;
    private SchedulerEventGeneratorMonitor monitor = null;
    private JobStateChangeListener listener = null;

    public EventDispatchTask (
        SchedulerEvent event,
        SchedulerEventGeneratorMonitor monitor)
    {
        this.monitor = monitor;
        this.listener = monitor.getListener();
        this.event = event;
    }

    public void run()
    {
        ResourceKey resourceKey =
            monitor.getMapping(event.getLocalId());

        // only if the resource has not been unregistered
        // in the meantime
        if (resourceKey != null) {
            listener.jobStateChanged(
                resourceKey, event.getLocalId(),
                event.getTimeStamp(), event.getState(),
                event.getExitCode());

                logger.debug("Job "+resourceKey.getValue()+
                    ": EventQueueThread: dispatched event "
                    + event.getState());
        }
    }
}
