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
