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
