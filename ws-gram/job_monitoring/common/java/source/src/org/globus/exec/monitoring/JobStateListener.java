package org.globus.exec.monitoring;

/**
 * Job State Change notification listener.
 *
 * The Managed Job Service implements this interface to receive job
 * state change notifications which are related to a particular Managed Job
 * Resource.
 */
public interface JobStateListener {
    /**
     * Method called by the JobStateMonitor when a job changes state.
     *
     * @param resourceKey
     *     Resource key associated with the job that changed state.
     * @param timestamp
     *     Time when the job state change occurred.
     * @param state
     *     New job state.
     * @param exitCode
     *     Integer code inidicating the job exit condition (if the state value
     *     is the done or failed job state.
     */
    public void jobStateChange(Object resourceKey, java.util.Date timestamp,
            int state, int exitCode);
}
