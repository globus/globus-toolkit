package org.globus.exec.monitoring;

class SegEvent
{
    private java.util.Date timestamp;
    private String localId;
    private int state;
    private int exitCode;
    static private Comparator comparator = new Comparator();

    public SegEvent(
            java.util.Date              timestamp,
            String                      localId,
            int                         state,
            int                         exitCode)
    {
        this.timestamp = timestamp;
        this.localId = localId;
        this.state = state;
        this.exitCode = exitCode;
    }
    public java.util.Date getTimeStamp() { return timestamp; }
    public String getLocalId() { return localId; }
    public int getState() { return state; }
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
            int s1, s2;
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

            if (s1 < s2)
            {
                return -1;
            }
            else if (s1 > s2)
            {
                return 1;
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
}
