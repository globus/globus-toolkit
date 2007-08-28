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

import org.globus.wsrf.ResourceKey;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.globus.exec.monitoring.seg.SchedulerEventGeneratorMonitor;

public class EventDispatchThread extends Thread
{
    /** Log4J logger */
    private static Log logger = LogFactory.getLog(EventDispatchThread.class);
    private boolean done = false;
    private EventDispatchQueue dispatchQueue = null;
    private SchedulerEventGeneratorMonitor monitor = null;
    private JobStateChangeListener listener = null;

    EventDispatchThread (String                 name,
                         EventDispatchQueue     queue)
    {
        super(name);
        this.dispatchQueue = queue;
        this.monitor = queue.getMonitor();
        this.listener = queue.getMonitor().getListener();
    }

    public synchronized void terminate()
    {
        this.done = true;
    }

    public void run()
    {
        while (!this.done)
        {
            SchedulerEvent event;

            synchronized (this.dispatchQueue)
            {
                while ((!this.done) && (dispatchQueue.size() == 0))
                {
                    try
                    {
                        dispatchQueue.wait();
                    }
                    catch (InterruptedException e) { }
                }
            }

            do
            {
                synchronized (dispatchQueue)
                {
                    if (dispatchQueue.size() > 0)
                    {
                        event = (SchedulerEvent) dispatchQueue.remove();
                        logger.debug("DispatchQueueSize: "+
                                     dispatchQueue.size());
                    }
                    else
                    {
                        event = null;
                    }
                }

                if (event != null)
                {
                    ResourceKey resourceKey =
                             monitor.getMapping(
                                event.getLocalId());

                    // only if the resource has not been unregistered
                    // in the meantime
                    if (resourceKey != null) {
                             listener.jobStateChanged(
                                  resourceKey,
                                  event.getLocalId(),
                                  event.getTimeStamp(),
                                  event.getState(),
                                  event.getExitCode());

                       logger.debug("Job "+resourceKey.getValue()+
                                    ": EventQueueThread: dispatched event "+
                                    event.getState());
                    }

                }
            }
            while ((!done) && (event != null));
        }
    }
}
