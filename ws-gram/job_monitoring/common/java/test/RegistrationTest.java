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
import org.globus.exec.monitoring.JobStateListener;
import org.globus.exec.monitoring.JobStateMonitor;
import org.globus.exec.monitoring.AlreadyRegisteredException;
import org.globus.exec.monitoring.NotRegisteredException;

/*
 * Test that an object can register/unregister mappings of job IDs.
 */
public class RegistrationTest
        extends junit.framework.TestCase
        implements JobStateListener
{
    private JobStateMonitor jsm;
    java.util.HashMap mappings = new java.util.HashMap();

    public RegistrationTest () {
        super();
    }

    protected void setUp() throws Exception
    {
        java.util.Properties props = System.getProperties();
        String str;

        str = (String) props.getProperty("SEG_PATH");

        if (str == null) {
            throw new Exception("SEG_PATH property not set");
        }
        java.io.File segPath = new java.io.File(str);
        String userName = 
                (String) props.getProperty("SEG_USER_NAME");
        if (userName == null) {
            throw new Exception("SEG_USER_NAME property not set");
        }

        str = (String) props.getProperty("SEG_MODULE_PATH");
        if (str == null) {
            throw new Exception("SEG_MODULE_PATH property not set");
        }
        java.io.File schedulerPath = new java.io.File(str);

        jsm = new JobStateMonitor(segPath, userName, schedulerPath, this, null);
    }

    public void testRegister()
    {
        try {
            String localId[] = { "localId1", "localId2", "localId3" };

            Object resourceKey[] = {
                new Integer(1),
                new Integer(2),
                new Integer(3)
            };

            for (int i = 0; i < localId.length; i++) {
                jsm.registerJobID(localId[i], resourceKey[i]);
            }

            for (int i = 0; i < localId.length; i++) {
                jsm.unregisterJobID(localId[i]);
            }
        } catch (AlreadyRegisteredException are) {
            assertNull("Unexpected AlreadyRegisteredException: "
                    + are.toString(),
                    are);
        } catch (NotRegisteredException nre) {
            assertNull("Unexpected NotRegisteredException: "
                    + nre.toString(),
                    nre);
        }
    }

    public void testBadUnregister()
    {
        boolean asserted = false;
        String localId[] = { "localId1", "localId2", "localId3" };

        Object resourceKey[] = {
            new Integer(1),
            new Integer(2),
            new Integer(3)
        };


        try {
            for (int i = 0; i < localId.length; i++) {
                jsm.registerJobID(localId[i], resourceKey[i]);
            }

            jsm.unregisterJobID("bogus");

        } catch (AlreadyRegisteredException are) {
            assertNull("Unexpected AlreadyRegisteredException: "
                    + are.toString(),
                    are);
        } catch (NotRegisteredException nre) {
            asserted = true;
        }

        try {
            for (int i = 0; i < localId.length; i++) {
                jsm.unregisterJobID(localId[i]);
            }
        } catch (NotRegisteredException nre) {
            assertNull("Unexpected NotRegisteredException: "
                    + nre.toString(),
                    nre);
        }

        assertTrue("Expected NotRegisteredException, but didn't get it",
                asserted);
    }

    public void jobStateChange(Object resourceKey, java.util.Date timeStamp,
        int jobState, int exitCode) {
    }

    public static void main(String [] args) {
        RegistrationTest t = new RegistrationTest();
        try {
            t.setUp();
            t.testRegister();
            t.testBadUnregister();
        } catch (Exception e) {
            System.err.println(e.toString());
        }
    }
}
