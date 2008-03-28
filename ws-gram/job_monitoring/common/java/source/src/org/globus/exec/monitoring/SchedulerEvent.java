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

import java.util.Date;
import org.globus.exec.generated.StateEnumeration;

/**
 * Class used internally by the JobStateMonitor to store events emmited by the
 * Scheduler Event Generator.
 */
public class SchedulerEvent {
    
    private java.util.Date timestamp;
    private String localId;
    private StateEnumeration state;
    private int exitCode;
    static private Comparator comparator = new Comparator();

    /**
     * Create a new SchedulerEvent.
     * 
     * Event contents cannot change after being created.
     */
    public SchedulerEvent(
        Date timestamp,
        String localId,
        StateEnumeration state,
        int exitCode) {

        this.timestamp = timestamp;
        this.localId = localId;
        this.state = state;
        this.exitCode = exitCode;
    }

    /** Retreive the value of the event's time stamp */
    public java.util.Date getTimeStamp() {

        return timestamp;
    }

    /** Retrieve the value of the event's local ID */
    public String getLocalId() {

        return localId;
    }

    /** Return the value of the event's state */
    public StateEnumeration getState() {

        return state;
    }

    /** Return the value of the event's exit code */
    public int getExitCode() {

        return exitCode;
    }

    public String toString() {

        StringBuffer sb = new StringBuffer();
        sb.append(localId);
        sb.append(" [");
        sb.append(timestamp.toString());
        sb.append("] ");
        sb.append(state.toString());
        return sb.toString();
    }

    /**
     * Return a reference to the comparator used to order events. Used by the
     * JobStateMonitor's event cache.
     */
    static public java.util.Comparator getComparator() {

        return comparator;
    }

    private static class Comparator
        implements java.util.Comparator {
        /**
         * Compare two SchedulerEvents. An event e1 is less than another e2 if
         * (in order of importance) it
         * <ul>
         * <li>occurs before the other</li>
         * <li>has a lower-value local id</li>
         * <li> has a lower-value state</li>
         * </ul>
         */
        public int compare(Object o1, Object o2)
            throws ClassCastException {

            SchedulerEvent e1, e2;
            int rc;
            StateEnumeration s1, s2;
            int ec1, ec2;

            e1 = (SchedulerEvent) o1;
            e2 = (SchedulerEvent) o2;

            rc = e1.timestamp.compareTo(e2.timestamp);

            if (rc != 0) {
                return rc;
            }

            rc = e1.localId.compareTo(e2.localId);

            if (rc != 0) {
                return rc;
            }

            s1 = e1.state;
            s2 = e2.state;

            if (!s1.equals(s2)) {
                if (s1.equals(StateEnumeration.Done)) {
                    return 1;
                } else if (s2.equals(StateEnumeration.Done)) {
                    return -1;
                } else if (s1.equals(StateEnumeration.Failed)) {
                    return 1;
                } else if (s2.equals(StateEnumeration.Failed)) {
                    return -1;
                } else if (s1.equals(StateEnumeration.StageOut)) {
                    return 1;
                } else if (s2.equals(StateEnumeration.StageOut)) {
                    return -1;
                } else if (s1.equals(StateEnumeration.Active)) {
                    return 1;
                } else if (s2.equals(StateEnumeration.Active)) {
                    return -1;
                } else if (s1.equals(StateEnumeration.Pending)) {
                    return -1;
                } else if (s2.equals(StateEnumeration.Pending)) {
                    return 1;
                } else if (s1.equals(StateEnumeration.StageIn)) {
                    return 1;
                } else if (s2.equals(StateEnumeration.StageIn)) {
                    return -1;
                }
            }

            ec1 = e1.exitCode;
            ec2 = e2.exitCode;

            if (ec1 < ec2) {
                return -1;
            } else if (ec1 > ec2) {
                return 1;
            } else {
                return 0;
            }
        }
    }
}
