package org.globus.exec.monitoring;

import org.globus.exec.generated.StateEnumeration;

class SegEvent
{
    private java.util.Date timestamp;
    private String localId;
    private StateEnumeration state;
    private int exitCode;
    static private Comparator comparator = new Comparator();

    public SegEvent(
            java.util.Date              timestamp,
            String                      localId,
            StateEnumeration            state,
            int                         exitCode)
    {
        this.timestamp = timestamp;
        this.localId = localId;
        this.state = state;
        this.exitCode = exitCode;
    }
    public java.util.Date getTimeStamp() { return timestamp; }
    public String getLocalId() { return localId; }
    public StateEnumeration getState() { return state; }
    public int getExitCode() { return exitCode; }

    static public java.util.Comparator getComparator() {
        return comparator;
    }

    private static class Comparator implements java.util.Comparator
    {
        public int compare(Object o1, Object o2)
                throws ClassCastException
        {
            SegEvent e1, e2;
            int rc;
            StateEnumeration s1, s2;
            int ec1, ec2;

            e1 = (SegEvent) o1;
            e2 = (SegEvent) o2;

            rc = e1.getTimeStamp().compareTo(e2.getTimeStamp());

            if (rc != 0) {
                return rc;
            }

            rc = e1.getLocalId().compareTo(e2.getLocalId());

            if (rc != 0) {
                return rc;
            }

            s1 = e1.getState();
            s2 = e2.getState();

            if (! s1.equals(s2)) {
                if (s1.equals(StateEnumeration.Done)) {
                    return -1;
                } else if (s2.equals(StateEnumeration.Done)) {
                    return 1;
                } else if (s1.equals(StateEnumeration.Failed)) {
                    return -1;
                } else if (s2.equals(StateEnumeration.Failed)) {
                    return 1;
                } else if (s1.equals(StateEnumeration.StageOut)) {
                    return -1;
                } else if (s2.equals(StateEnumeration.StageOut)) {
                    return 1;
                } else if (s1.equals(StateEnumeration.Active)) {
                    return -1;
                } else if (s2.equals(StateEnumeration.Active)) {
                    return 1;
                } else if (s1.equals(StateEnumeration.Pending)) {
                    return -1;
                } else if (s2.equals(StateEnumeration.Pending)) {
                    return -1;
                } else if (s1.equals(StateEnumeration.StageIn)) {
                    return -1;
                } else if (s2.equals(StateEnumeration.StageIn)) {
                    return 1;
                }
            }

            ec1 = e1.getExitCode();
            ec2 = e2.getExitCode();

            if (ec1 < ec2)
            {
                return -1;
            }
            else if (ec1 > ec2)
            {
                return 1;
            }
            else
            {
                return 0;
            }
        }
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
}
