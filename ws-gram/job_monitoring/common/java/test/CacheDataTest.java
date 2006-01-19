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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.exec.monitoring.JobStateListener;
import org.globus.exec.monitoring.JobStateMonitor;
import org.globus.exec.monitoring.AlreadyRegisteredException;
import org.globus.exec.monitoring.NotRegisteredException;

/**
 * Test that data in the soft state cache gets replayed.
 * <b>Required</b> system properties:
 * <dl>
 *   <dt>SEG_PATH</dt>
 *   <dt>SEG_USER_NAME</dt>
 *   <dt>SEG_MODULE_PATH</dt>
 *   <dt>SEG_FAKER</dt>
 * </dl>
 */
public class CacheDataTest
        extends junit.framework.TestCase
        implements JobStateListener
{
    JobStateMonitor jsm;
    String logFaker;
    String fakeData;
    java.util.HashMap jobs = new java.util.HashMap();
    java.util.LinkedList delay = new java.util.LinkedList();
    boolean done = false;

    int notok = 0;
    private static Log logger = LogFactory.getLog(CacheDataTest.class);


    public CacheDataTest() {
        super();
    }

    protected void setUp()
            throws Exception
    {
        java.util.Properties props = System.getProperties();
        String str;

        str = (String) props.getProperty("SEG_PATH");
        if (str == null) {
            throw new Exception("SEG_PATH property is not set.\n");
        }
        java.io.File segPath = new java.io.File(str);
        String userName =
                (String) props.getProperty("SEG_USER_NAME");
        if (userName == null) {
            throw new Exception("SEG_USER_NAME property is not set.\n");
        }
        str = (String) props.getProperty("SEG_MODULE_PATH");
        if (str == null) {
            throw new Exception("SEG_MODULE_PATH property is not set.\n");
        }
        java.io.File schedulerPath = new java.io.File(str);

        logFaker = (String) props.getProperty("SEG_FAKER");
        if (logFaker == null) {
            throw new Exception("SEG_FAKER property is not set.\n");
        }

        jsm = new JobStateMonitor(segPath, userName, schedulerPath, this,
                null);
    }

    public void testSoftStateCache() throws java.io.IOException{
        Process faker;
        java.io.BufferedReader reader;
        jsm.start(new java.util.Date());
        faker = Runtime.getRuntime().exec(logFaker);
        reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(faker.getInputStream()));
        String line;

        Thread thr = new Thread() {
            public void run() {
                synchronized(delay) {
                    while (!done) {
                        logger.debug("waiting 30 secs");
                        try {
                            delay.wait(30 * 1000);
                        } catch (InterruptedException ie) {
                        }

                        while (! delay.isEmpty()) {
                            JobTransitions t = (JobTransitions) 
                                    delay.removeFirst();

                            try {
                                logger.debug("registering " + t.jobId);
                                jsm.registerJobID(t.jobId, t.jobId);
                            } catch (AlreadyRegisteredException are) {
                            }
                        }
                    }
                }
            }
        };

        thr.start();

        while ((line = reader.readLine()) != null) {
            java.util.StringTokenizer st =
                    new java.util.StringTokenizer(line, ";");
            boolean addit = false;

            logger.debug("line is " + line);

            JobTransitions t;
            
            try {
                String when = st.nextToken();
                String jobid = st.nextToken();
                String state = st.nextToken();

                synchronized (jobs) {
                    t = (JobTransitions) jobs.get(jobid);
                }

                if (t == null) {
                    t = new JobTransitions(jobid);
                    addit = true;
                }

                if (state.equals("pending")) {
                    // New job:
                    t.pending[0] = new java.util.Date(Long.parseLong(when));
                } else if (state.equals("active")) {
                    t.active[0] = new java.util.Date(Long.parseLong(when));
                } else if (state.equals("failed")) {
                    t.failed[0] = new java.util.Date(Long.parseLong(when));
                } else if (state.equals("done")) {
                    t.done[0] = new java.util.Date(Long.parseLong(when));
                }

                if (addit) {
                    synchronized (jobs) {
                        jobs.put(jobid, t);
                    }
                    synchronized (delay) {
                        delay.addLast(t);
                    }
                }
            } catch (java.util.NoSuchElementException nsee) {
            }
        }
        synchronized (delay) {
            done = true;
        }

        try {
            thr.join();
        } catch (InterruptedException ie) {
        }

        synchronized (jobs) {
            while (! jobs.isEmpty()) {
                try {
                    jobs.wait();
                } catch (InterruptedException ie) {
                }
            }
        }

        assertTrue(notok == 0);
        jsm.stop();
    }

    public void jobStateChange(Object resourceKey, java.util.Date timeStamp,
            int jobState, int exitCode)
    {
        JobTransitions t;
        boolean done = false;

        synchronized (jobs) {
            t = (JobTransitions) jobs.get(resourceKey);
        }
        switch (jobState) {
            case 1:
                t.pending[1] = timeStamp;
                break;
            case 2:
                t.active[1] = timeStamp;
                break;
            case 4:
                t.failed[1] = timeStamp;
                done = true;
                break;
            case 8:
                t.done[1] = timeStamp;
                done = true;
                break;
        }

        if (done)
        {
            if (timesMismatch(t.pending) || timesMismatch(t.done) ||
                timesMismatch(t.active) || timesMismatch(t.failed)) {
                notok++;
            }

            synchronized (jobs) {
                jobs.remove(t.jobId);

                if (jobs.isEmpty()) {
                    jobs.notify();
                }
            }
        }
    }

    private boolean timesMismatch(java.util.Date times[]) {
        if (times[0] == times[0]) {
            return false;
        } else if (times[0] == null && times[1] != null) {
            return true;
        } else if (times[0] != null && times[1] == null) {
            return true;
        } else if (times[0].compareTo(times[1]) == 0) {
            return false;
        } else {
            return true;
        }
    }

    private class JobTransitions {
        public JobTransitions(String jobid) { jobId = jobid; }
        String jobId;
        java.util.Date pending[] = new java.util.Date[2];
        java.util.Date active[] = new java.util.Date[2];
        java.util.Date done[] = new java.util.Date[2];
        java.util.Date failed[] = new java.util.Date[2];
    }
}
