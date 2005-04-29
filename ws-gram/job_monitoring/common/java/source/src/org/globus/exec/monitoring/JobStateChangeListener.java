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

import org.globus.exec.generated.StateEnumeration;
import org.globus.wsrf.ResourceKey;

/**
 * Job State Change notification listener.
 *
 * The Managed Job Service implements this interface to receive job
 * state change notifications which are related to a particular Managed Job
 * Resource.
 */
public interface JobStateChangeListener {
    /**
     * Method called by the JobStateMonitor when a job changes state.
     *
     * @param resourceKey
     *     Resource key associated with the job that changed state.
     * @param localJobId
     *     Local Job ID for the job which changed state. There may be multiple
     *     local job IDs for a single job for some schedulers.
     * @param timestamp
     *     Time when the job state change occurred.
     * @param state
     *     New job state.
     * @param exitCode
     *     Integer code inidicating the job exit condition (if the state value
     *     is the done or failed job state.
     */
    public void jobStateChanged(
            ResourceKey                     resourceKey,
            String                          localJobId,
            java.util.Date                  timestamp,
            StateEnumeration                state,
            int                             exitCode);
}
