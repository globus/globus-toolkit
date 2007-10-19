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
package org.globus.usage.report.combined;

import java.util.List;
import java.util.ArrayList;
import java.io.PrintStream;

public class SlotLogHelper {

    protected static final long SEC_PER_HOUR = 60 * 60;
    protected static final long SEC_PER_DAY =  SEC_PER_HOUR * 24;
    protected static final long SEC_PER_WEEK =  SEC_PER_DAY * 7;
    protected static final long SEC_PER_MONTH =  SEC_PER_DAY * 30;
    protected static final long SEC_PER_YEAR =  SEC_PER_MONTH * 12;

    protected List slots = new ArrayList();

    protected void initializeSlots() {
        this.slots.add(new Slot(1));
        this.slots.add(new Slot(11));
        this.slots.add(new Slot(101));
        this.slots.add(new Slot(1001));
        this.slots.add(new Slot(10001));
        this.slots.add(new Slot(100001));
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
        String[] names = { "less than 1", "1-10", "11-100", "101-1000", "1001-10000", "10001-100000" };
        for (int i = 0; i < this.slots.size(); i++) {
            Slot slot = (Slot)this.slots.get(i);
            out.println("  <slot>");
            out.println("   <bucket>" + slot.getTime() + "</bucket>");
            out.println("   <bucketStr>" + names[i] + "</bucketStr>");
            out.println("   <count>" + slot.getCount() + "</count>");
            out.println("  </slot>");
        }
    }
    
    // time in sec
    public static String formatTimeSec(long time) {
        
        StringBuffer str = new StringBuffer();

        long weeks = time / SEC_PER_WEEK;
        if (weeks > 0) {
            if (str.length() != 0) str.append(", ");
            str.append((weeks == 1) ? "1 week" : weeks + " weeks");
            time -= weeks * SEC_PER_WEEK;
        }
        else
        {
            return "0 weeks";
        }
    
	return str.toString();
    }

    protected Slot getSlot(long mseconds) {
        Slot prevSlot = (Slot)this.slots.get(0);

        if (mseconds < prevSlot.getTime())
        {
            return prevSlot;
        }

        for (int i = 1; i < this.slots.size(); i++) {
            Slot slot = (Slot)this.slots.get(i);
            if (mseconds >= prevSlot.getTime() &&
                mseconds < slot.getTime()) {

                return slot;
            }
            prevSlot = slot;
        }
        return prevSlot;
    }
}

