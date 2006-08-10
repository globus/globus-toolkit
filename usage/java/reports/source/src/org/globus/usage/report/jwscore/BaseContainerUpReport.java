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
package org.globus.usage.report.jwscore;

import java.util.List;
import java.util.ArrayList;
import java.io.PrintStream;

public class BaseContainerUpReport {

    protected static final long SEC_PER_HOUR = 60 * 60;
    protected static final long SEC_PER_DAY =  SEC_PER_HOUR * 24;
    protected static final long SEC_PER_MONTH =  SEC_PER_DAY * 30;
    protected static final long SEC_PER_YEAR =  SEC_PER_MONTH * 12;

    protected List slots = new ArrayList();

    protected void initializeSlots() {
        // 0 sec
        this.slots.add(new Slot(0));

        // 1 minute
        this.slots.add(new Slot(60 * 1));

        // 2 minutes
        this.slots.add(new Slot(60 * 2));

        // 5 minutes
        this.slots.add(new Slot(60 * 5));

        // minutes
        for (int i=1;i<=6;i++) {
            this.slots.add(new Slot(60 * i * 10));
        }
        // hours
        for (int i=1;i<=8;i++) {
            this.slots.add(new Slot(SEC_PER_HOUR * i * 3));
        }
        // days
        for (int i=1;i<=10;i++) {
            this.slots.add(new Slot(SEC_PER_DAY * i * 3));
        }
        // months
        for (int i=1;i<=6;i++) {
            this.slots.add(new Slot(SEC_PER_MONTH * i * 2));
        }
    }

    static class Slot {

        private int count;
        private long time;
        
        public Slot(long time) {
            this.time = time;
        }
        
        public void increment() {
            this.count++;
        }
        
        public int getCount() {
            return this.count;
        }
        
        public long getTime() {
            return this.time;
        }
    }

    public void output(PrintStream out) {
        for (int i = 0; i< this.slots.size(); i++) {
            Slot slot = (Slot)this.slots.get(i);
            out.println("  <slot>");
            out.println("   <time>" + slot.getTime() + "</time>");
            out.println("   <timeStr>" + formatTimeSec(slot.getTime()) + "</timeStr>");
            out.println("   <count>" + slot.getCount() + "</count>");
            out.println("  </slot>");
        }
    }
    
    // time in sec
    public static String formatTimeSec(long time) {
        
        if (time < 60) {
            return ((time == 1) ? "1 second" : time + " seconds");
	} 

        StringBuffer str = new StringBuffer();

        long years = time / SEC_PER_YEAR;
        if (years > 0) {
            str.append((years == 1) ? "1 year" : years + " years");
            time -= years * SEC_PER_YEAR;
        }

        long months = time / SEC_PER_MONTH; // assumes 30 days per month
        if (months > 0) {
            if (str.length() != 0) str.append(", ");
            str.append((months == 1) ? "1 month" : months + " months");
            time -= months * SEC_PER_MONTH;
        }
    
	long days = time / SEC_PER_DAY;
    
	if (days > 0) {
            if (str.length() != 0) str.append(", ");
	    str.append((days == 1) ? "1 day" :  days + " days");
	    time -= days *  SEC_PER_DAY;
	}
    
	long hours = time / SEC_PER_HOUR;
    
	if (hours > 0) {
	    if (str.length() != 0) str.append(", ");
	    str.append((hours == 1) ? "1 hour" : hours + " hours");
	    time -= hours * SEC_PER_HOUR;
	}
        
	long mins = time / 60;
        
	if (mins > 0) {
	    if (str.length() != 0) str.append(", ");
	    str.append((mins == 1) ? "1 minute" : mins + " minutes");
	    time -= mins * 60;
	}
    
	long sec = time;
    
	if (sec > 0) {
	    if (str.length() != 0) str.append(", ");
	    str.append((sec == 1) ? "1 second" : sec + " seconds");
	}
    
	return str.toString();
    }

    protected Slot getSlot(long mseconds) {
        Slot prevSlot = (Slot)this.slots.get(0);
        for (int i = 1; i < this.slots.size(); i++) {
            Slot slot = (Slot)this.slots.get(i);
            if (mseconds >= prevSlot.getTime() &&
                mseconds < slot.getTime()) {
                return prevSlot;
            }
            prevSlot = slot;
        }
        return prevSlot;
    }
}

