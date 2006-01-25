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
