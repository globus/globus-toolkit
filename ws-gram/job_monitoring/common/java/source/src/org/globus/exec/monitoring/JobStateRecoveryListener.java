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

/**
 * Interface for recovery information updates.
 * <p>
 * Objects which provide a persistent store for recoverability data
 * can implement this interface to receive periodic updates of the timestamp
 * which a Job State Monitor would use if it were to be restarted after being
 * shut down (normally or abnormally).
 * </p>
 */
public interface JobStateRecoveryListener {
    /**
     * Update the value of the timestamp used for recovering this
     * JobStatemonitor instance.
     *
     * @param monitor
     *     JobStateMonitor which is updating its timestamp.
     * @param timeStamp
     *     New value of the recovery timestamp. This should be passed to
     *     the #JobStateMonitor.start() method when it is restarted.
     */
    public void updateJobMonitorRecoveryTimeStamp(JobStateMonitor monitor,
            java.util.Date timeStamp);
}
