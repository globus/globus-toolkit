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

import java.sql.ResultSet;

import java.text.SimpleDateFormat;

import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Vector;


public class HistogramParser {
    static private SimpleDateFormat dayFormat;
    static private SimpleDateFormat monthFormat;
    static private SimpleDateFormat sqlDateFormat;

    static {
        dayFormat = new SimpleDateFormat("MMM d,''yy");
        monthFormat = new SimpleDateFormat("MMM, ''yy");
        sqlDateFormat = new SimpleDateFormat("yyyy-MM-dd");
    }

    private String title;
    private String output;
    private String axisName;
    private HashMap uniqueItems; // itemName -> ItemEntry
    private Entry[] entries; // indexed by step number
    private int index;
    private long totalData;
    private TimeStep ts;
    private SimpleDateFormat dateFormat;
    private String stepDuration;

    public HistogramParser(String t, String o, String a, TimeStep ts) {
        uniqueItems = new HashMap(5);
        title = t;
        output = o;
        axisName = a;
        entries = new Entry[ts.getSteps()];
        index = -1;
        totalData = 0;
        ts = new TimeStep(ts.getTime(), ts.getStepSize(), ts.getSteps());
        if (ts.getStepSize() == Calendar.MONTH) {
            dateFormat = monthFormat;
            stepDuration = "month";
        } else {
            dateFormat = dayFormat;
            stepDuration = "day";
        }
    }

    public void nextEntry() {
        entries[++index] = new Entry(ts.getTime(), ts.stepTime());
    }

    public void addData(String item) {
        this.addData(item, 1.0);
    }

    public void addData(String item, double data) {
        ItemEntry entry = (ItemEntry) uniqueItems.get(item);
        if (entry == null) {
            entry = new ItemEntry(item);
            uniqueItems.put(item, entry);
        }
        entry.add(data);

        entries[index].addData(item, data);
        totalData += data;
    }

    public double getData(String item) {
        ItemEntry entry = (ItemEntry) uniqueItems.get(item);
        if (entry == null) {
            return 0.0;
        }
        else
        {
            return entry.get();
        }
    }

    public void output(PrintStream io) {
        io.println("<histogram>");
        io.println(" <title>" + title + "</title>");
        io.println(" <output>" + output + "</output>");
        io.println(" <axis>" + axisName + "</axis>");

        Iterator iter = uniqueItems.keySet().iterator();
        List itemEntries = new Vector();

        while (iter.hasNext()) {
            String itemName = (String) iter.next();
            itemEntries.add(uniqueItems.get(itemName));
        }
        Collections.sort(itemEntries);

        int otherCount = 0;
        {
            ListIterator li = itemEntries.listIterator();
            while (li.hasNext()) {
                ItemEntry ie = (ItemEntry) li.next();
                if ((ie.get() / totalData) < .005) {
                    otherCount++;
                }
            }
        }

        for (int i = 0; i < entries.length; i++) {
            io.println(" <entry>");
            io.println("\t<start-date>"
                       + formatDate(entries[i].getStartDate())
                       + "</start-date>");
            io.println("\t<end-date>"
                       + formatDate(entries[i].getEndDate())
                       + "</end-date>");

            long remaining = totalData;
            ListIterator li = itemEntries.listIterator();

            if (otherCount > 0) {
                double otherValue = 0;
                io.println("\t<item>");
                io.println("\t\t<name> other </name>");

                while (otherCount-- > 0) {
                    ItemEntry ie = (ItemEntry) li.next();

                    io.println("\t\t<sub-item>");
                    io.println("\t\t\t<name>" + ie.name
                            + "</name>");
                    io.println("\t\t\t<single-value>"
                            + entries[i].getData(ie.name)
                            + "</single-value>");
                    io.println("\t\t</sub-item>");
                    otherValue += entries[i].getData(ie.name);
                }
                io.println("\t\t<single-value>" + (long) otherValue
                        + "</single-value>");
                io.println("\t\t<value>" + remaining + "</value>");
                io.println("\t</item>");
                remaining -= otherValue;
            }

            while (li.hasNext()) {
                ItemEntry ie = (ItemEntry) li.next();
                double value = entries[i].getData(ie.name);

                io.println("\t<item>");
                io.println("\t\t<name>" + ie.name + "</name>");

                io.println("\t\t<single-value>" + (long) value
                        + "</single-value>");

                io.println("\t\t<value>" + remaining + "</value>");
                io.println("\t</item>");

                remaining -= value;
            }
            io.println(" </entry>");
        }

        io.println(" <slots>");
        io.println("\t<start-date>" + formatDate(entries[0].getStartDate())
                + "</start-date>");
        io.println("\t<end-date>"
                + formatDate(entries[entries.length - 1].getStartDate())
                + "</end-date>");

        outputSlots(io);

        io.println(" </slots>");
        io.println("</histogram>");
    }

    public void outputSlots(PrintStream io) {
        Iterator iter = uniqueItems.keySet().iterator();
        List itemEntries = new Vector();

        while (iter.hasNext()) {
            String itemName = (String) iter.next();
            itemEntries.add(uniqueItems.get(itemName));
        }
        Collections.sort(itemEntries);

        ListIterator li = itemEntries.listIterator();
        while (li.hasNext()) {
            ItemEntry ie = (ItemEntry) li.next();

            io.println("\t<item>");
            io.println("\t\t<name>" + ie.name + "</name>");
            io.println("\t\t<single-value>"
                    + ie.get()
                    + "</single-value>");
            io.println("\t</item>");
        }
    }
    
    public void upload(DatabaseRetriever dbr) throws Exception {
        for (int i = 0; i < entries.length; i++) {
            ResultSet rs;
            String dateString = sqlDateFormat.format(entries[i].getStartDate());
            String durationString = "1 " + stepDuration;
            long id;

            dbr.update("INSERT INTO histogram_metadata " +
                "(report_name, report_date, duration, title, axis) " +
                "VALUES('" + output + "', '" + dateString + "', '" +
                durationString + "', '" + title + "', '" + axisName + "');");
            
            rs = dbr.retrieve("SELECT id "
                       + "FROM histogram_metadata "
                       + "WHERE report_name = '" + output + "' "
                       + "AND report_date = '" + dateString + "' "
                       + "AND duration = '1 " + durationString + "' "
                       + "AND title = '" + title + "' "
                       + "AND axis = '" + axisName + "' ");

            id = -1;
            while (rs.next()) {
                id = rs.getLong(1);
            }
            rs.close();

            if (id == -1) {
                throw new Exception("Error determining id");
            }

            Iterator iter = uniqueItems.keySet().iterator();

            while (iter.hasNext()) {
                String itemName = (String) iter.next();

                dbr.update("INSERT into histograms(id, item, value) "
                         + "VALUES(" + id + ", '" + itemName + "', "
                         + entries[i].getData(itemName) + "');");
            }
        }
    }

    private String formatDate(Date date) {
        return dateFormat.format(date);
    }

    public static class Entry {
        private Date start;
        private Date end;
        private HashMap itemMap;

        public Entry(Date start, Date end) {
            itemMap = new HashMap(5);
            this.start = start;
            this.end = end;
        }

        public Date getStartDate() {
            return start;
        }

        public Date getEndDate() {
            return start;
        }

        public void addData(String keyName, double data) {
            ItemEntry entry = (ItemEntry) itemMap.get(keyName);
            if (entry == null) {
                entry = new ItemEntry(keyName, 0);
                itemMap.put(keyName, entry);
            }
            entry.add(data);
        }

        public double getData(String keyName) {
            ItemEntry entry = (ItemEntry) itemMap.get(keyName);
            if (entry == null) {
                return 0.0;
            } else {
                return entry.get();
            }
        }
    }

    public static class ItemEntry implements Comparable {
        private String name;
        private double data;

        public ItemEntry(String name) {
            this.name = name;
            this.data = 0;
        }

        public ItemEntry(String name, double in) {
            this.name = name;
            this.data = in;
        }

        public void add(double in) {
            this.data += in;
        }

        public double get() {
            return this.data;
        }

        public int compareTo(Object o) throws ClassCastException {
            ItemEntry ie = (ItemEntry) o;
            if (data > ie.data) {
                return 1;
            } else if (get() == ie.data) {
                return 0;
            } else {
                return -1;
            }
        }

    }
}
