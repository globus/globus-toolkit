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
package org.globus.usage.report.common;

import java.io.IOException;
import java.io.PrintStream;

import java.text.SimpleDateFormat;

import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Vector;


public class SlottedHistogramParser extends HistogramParser {
    private Slotter slots;

    public SlottedHistogramParser(String t, String o, TimeStep ts,
            String rangeName)
    throws IOException {
        super(t, o, "count", ts);
        slots = new Slotter(rangeName);
    }

    public void addData(double value) {
        this.slots.addValue(value, 1);
    }

    public void addData(double value, long valueToAdd) {
        this.slots.addValue(value, valueToAdd);
        super.addData(slots.whichSlotString(value), valueToAdd);
    }

    public void outputSlots(PrintStream io) {
        slots.output(io);
    }

    public int getNumSlots() {
        return slots.getNumSlots();
    }

    public long getSlotThreshold(int which) {
        return slots.getSlotThreshold(which);
    }
        
    public String getSlotName(int which) {
        return slots.getSlotName(which);
    }
}
