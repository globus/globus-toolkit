package org.globus.exec.monitoring;

/**
 * Job ID Not registered.
 * 
 * Thrown when a jobid is requested for unregistration which has not been
 * registered.
 */
public class NotRegisteredException extends Exception
{
    String localId;


    public NotRegisteredException(String localId)
    {
        this.localId = localId;
    }
}
