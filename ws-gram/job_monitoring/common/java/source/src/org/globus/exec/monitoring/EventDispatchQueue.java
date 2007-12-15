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

import java.util.LinkedList;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.globus.exec.monitoring.seg.SchedulerEventGeneratorMonitor;

public class EventDispatchQueue {
    
    /** Log4J logger */
    private static Log logger = LogFactory.getLog(EventDispatchQueue.class);
    private LinkedList cachedEvents = null;
    private SchedulerEventGeneratorMonitor monitor = null;
    private boolean initialized = false;

    public EventDispatchQueue(SchedulerEventGeneratorMonitor monitor) {

        this.cachedEvents = new LinkedList();
        this.monitor = monitor;
        this.initialized = false;
    }

    private synchronized void initialize() {

        // start all run queue instances
        // 1 thread is enough
        EventDispatchThread dispatchThread =
            new EventDispatchThread("EventDispatchThread", this);
        dispatchThread.setDaemon(true);
        dispatchThread.start();

        initialized = true;
    }

    public synchronized void add(
        SchedulerEvent event) {

        if (!initialized) {
            initialize();
        }
        cachedEvents.add(event);
        notify();
    }

    public synchronized SchedulerEvent remove() {

        return (SchedulerEvent) cachedEvents.removeFirst();
    }

    public synchronized int size() {

        return cachedEvents.size();
    }

    synchronized SchedulerEventGeneratorMonitor getMonitor() {

        return this.monitor;
    }

}
