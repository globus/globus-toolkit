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

import java.util.Vector;
import java.util.HashMap;
import java.util.Iterator;

import java.io.IOException;
import java.io.PrintStream;

public class HistogramParser {

    private String title;

    private String output;

    private String axisName;

    private HashMap uniqueItems;

    private Entry[] entries;

    private int index;

    private long totalData;

    private boolean rangeSlotted;

    private Slotter slots;

    public HistogramParser(String t, String o, String a, int stepNumber) {
        uniqueItems = new HashMap(5);
        title = t;
        output = o;
        axisName = a;
        entries = new Entry[stepNumber];
        index = -1;
        rangeSlotted = false;
        totalData = 0;
    }

    public HistogramParser(String t, String o, int stepNumber, String rangeName) 
    	throws IOException {
        uniqueItems = new HashMap(5);
        title = t;
        output = o;
        axisName = "count";
        entries = new Entry[stepNumber];
        index = -1;
        rangeSlotted = true;
        slots = new Slotter(rangeName);
        totalData = 0;
    }

    public void nextEntry(String start, String endString) {
        index++;
        entries[index] = new Entry();
        entries[index].addStartDate(start);
        entries[index].addEndDate(endString);
    }

    public void addData(String item) {
        this.addData(item, 1.0);
    }

    public void addData(String item, double data) {
        if (!uniqueItems.containsKey(item)) {
            uniqueItems.put(item, new ItemEntry(0));
        }
        entries[index].addData(item, data);
        uniqueItems.put(item, ((ItemEntry) uniqueItems.get(item)).add(data));
        totalData += data;
    }

    public void addRangedData(double value) {
        this.slots.addValue(value, 1);
    }

    public void addRangedData(double value, int valueToAdd) {
        this.slots.addValue(value, valueToAdd);
        this.addData(slots.whichSlot(value), valueToAdd);
    }

    public void output(PrintStream io) {
        io.println("<histogram>");
        io.println(" <title>" + title + "</title>");
        io.println(" <output>" + output + "</output>");
        io.println(" <axis>" + axisName + "</axis>");

        String[] itemNames = new String[uniqueItems.size()];
        String itemName;

        Iterator iter = uniqueItems.keySet().iterator();
        while (iter.hasNext()) {
            int x = 0;
            itemName = (String) iter.next();
            while (x < itemNames.length && itemNames[x] != ""
                    && itemNames[x] != null) {
                if (((ItemEntry) uniqueItems.get(itemName)).get() < ((ItemEntry) uniqueItems
                        .get(itemNames[x])).get()) {
                    String temp = itemNames[x];
                    itemNames[x] = itemName;
                    itemName = temp;
                }
                x++;
            }
            itemNames[x] = itemName;
        }
        Vector other = new Vector();
        iter = uniqueItems.keySet().iterator();
        while (iter.hasNext()) {
            itemName = (String) iter.next();
            if (((ItemEntry) uniqueItems.get(itemName)).get() / totalData < .005) {
                other.add(itemName);
            }
        }
        for (int i = 0; i < entries.length; i++) {
            io.println(" <entry>");
            io.println("\t<start-date>" + entries[i].getStartDate()
                    + "</start-date>");
            io
                    .println("\t<end-date>" + entries[i].getEndDate()
                            + "</end-date>");

            int itemIndex = 0;
            if (other.size() > 0) {
                double otherValue = 0;
                io.println("\t<item>");
                io.println("\t\t<name> other </name>");

                while (other.contains(itemNames[itemIndex])) {
                    io.println("\t\t<sub-item>");
                    io.println("\t\t\t<name>" + itemNames[itemIndex]
                            + "</name>");
                    io.println("\t\t\t<single-value>"
                            + entries[i].getData(itemNames[itemIndex])
                            + "</single-value>");
                    io.println("\t\t</sub-item>");
                    otherValue += entries[i].getData(itemNames[itemIndex]);
                    itemIndex++;
                }
                io.println("\t\t<single-value>" + (int) otherValue
                        + "</single-value>");
                for (int x = itemIndex; x < itemNames.length; x++) {
                    otherValue += entries[i].getData(itemNames[x]);
                }
                io.println("\t\t<value>" + otherValue + "</value>");
                io.println("\t</item>");
            }

            while (itemIndex < itemNames.length) {
                io.println("\t<item>");
                io.println("\t\t<name>" + itemNames[itemIndex] + "</name>");

                double value = entries[i].getData(itemNames[itemIndex]);
                io.println("\t\t<single-value>" + (int) value
                        + "</single-value>");

                itemIndex++;
                for (int x = itemIndex; x < itemNames.length; x++) {
                    value += entries[i].getData(itemNames[x]);
                }
                io.println("\t\t<value>" + value + "</value>");
                io.println("\t</item>");
            }
            io.println(" </entry>");
        }
        if (!rangeSlotted) {
            System.out.println(" <slots>");
            System.out.println("\t<start-date>" + entries[0].getStartDate()
                    + "</start-date>");
            System.out.println("\t<end-date>"
                    + entries[entries.length - 1].getStartDate()
                    + "</end-date>");
            Iterator iter2 = uniqueItems.keySet().iterator();
            while (iter2.hasNext()) {
                System.out.println("\t<item>");
                itemName = (String) iter2.next();
                System.out.println("\t\t<name>" + itemName + "</name>");
                System.out.println("\t\t<single-value>"
                        + ((ItemEntry) uniqueItems.get(itemName)).get()
                        + "</single-value>");
                System.out.println("\t</item>");
            }
            System.out.println(" </slots>");
        } else if (rangeSlotted) {
            System.out.println(" <slots>");
            System.out.println("\t<start-date>" + entries[0].getStartDate()
                    + "</start-date>");
            System.out.println("\t<end-date>"
                    + entries[entries.length - 1].getStartDate()
                    + "</end-date>");
            slots.output(io);
            System.out.println(" </slots>");
        }
        io.println("</histogram>");
    }

    public static class Entry {
        private String startDate;

        private String endDate;

        private HashMap itemMap;

        public Entry() {
            startDate = "";
            endDate = "";
            itemMap = new HashMap(5);
        }

        public void addStartDate(String start) {
            startDate = start;
        }

        public void addEndDate(String endString) {
            endDate = endString;
        }

        public String getStartDate() {
            return startDate;
        }

        public String getEndDate() {
            return endDate;
        }

        public void addData(String keyName, double data) {
            if (itemMap.containsKey(keyName)) {
                itemMap.put(keyName, ((ItemEntry) itemMap.get(keyName))
                        .add(data));
            } else {
                itemMap.put(keyName, new ItemEntry(data));
            }
        }

        public double getData(String keyName) {
            if (itemMap.containsKey(keyName)) {
                return ((ItemEntry) itemMap.get(keyName)).get();
            } else {
                return 0.0;
            }
        }
    }

    public static class ItemEntry {
        private double data;

        public ItemEntry(double in) {
            data = in;
        }

        public ItemEntry add(double in) {
            data += in;
            return new ItemEntry(data);
        }

        public double get() {
            return data;
        }

    }
}
