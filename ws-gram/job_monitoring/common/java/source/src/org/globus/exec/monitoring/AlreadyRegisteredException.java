package org.globus.exec.monitoring;

/**
 * Job ID Already Registered.
 *
 * Thrown when a jobid is requested for registration which has already been
 * registered.
 */
public class AlreadyRegisteredException extends Exception
{
    String localId;

    public AlreadyRegisteredException(String localId)
    {
        this.localId = localId;
    }
}
