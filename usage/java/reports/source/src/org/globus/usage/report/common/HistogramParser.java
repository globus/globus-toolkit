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
import java.sql.SQLException;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;

import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Locale;
import java.util.Vector;

public class HistogramParser {
    static protected SimpleDateFormat dayFormat;
    static protected SimpleDateFormat monthFormat;
    static protected SimpleDateFormat sqlDateFormat;
    static protected DecimalFormat valueFormat;

    static {
        valueFormat = (DecimalFormat) NumberFormat.getInstance(Locale.US);
        valueFormat.setMaximumFractionDigits(3);
        valueFormat.setGroupingUsed(false);
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
    private double totalData;
    protected TimeStep ts;
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
        this.ts = new TimeStep(ts);

        if (ts.getStepSize() == Calendar.MONTH) {
            dateFormat = monthFormat;
            stepDuration = "month";
        } else {
            dateFormat = dayFormat;
            stepDuration = "day";
        }
    }

    public void nextEntry() {
        nextEntry(new Entry(ts.getTime(), ts.stepTime()));
    }

    protected void nextEntry(Entry e) {
        entries[++index] = e;
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

    protected Iterator itemEntryIterator() {
        return uniqueItems.entrySet().iterator();
    }

    protected double getTotal() {
        return totalData;
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

            double remaining = entries[i].getTotal();
            ListIterator li = itemEntries.listIterator();

            if (otherCount > 0) {
                double otherValue = 0;
                io.println("\t<item>");
                io.println("\t\t<name> other </name>");

                for (int j = 0; j <  otherCount; j++) {
                    ItemEntry ie = (ItemEntry) li.next();

                    io.println("\t\t<sub-item>");
                    io.println("\t\t\t<name>" + ie.name
                            + "</name>");
                    io.println("\t\t\t<single-value>"
                            + valueFormat.format(entries[i].getData(ie.name))
                            + "</single-value>");
                    io.println("\t\t</sub-item>");
                    otherValue += entries[i].getData(ie.name);
                }
                io.println("\t\t<single-value>"
                        + valueFormat.format(otherValue) + "</single-value>");
                io.println("\t\t<value>" + remaining + "</value>");
                io.println("\t</item>");
                remaining -= otherValue;
            }

            while (li.hasNext()) {
                ItemEntry ie = (ItemEntry) li.next();
                double value = entries[i].getData(ie.name);

                io.println("\t<item>");
                io.println("\t\t<name>" + ie.name + "</name>");

                io.println("\t\t<single-value>"
                        + valueFormat.format(value) + "</single-value>");

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
                    + valueFormat.format(ie.get())
                    + "</single-value>");
            io.println("\t</item>");
        }
    }

    protected long getReportId(DatabaseRetriever dbr, Entry e) {
        long id = -1;
        String dateString = sqlDateFormat.format(e.getStartDate());
        String durationString = ts.getStepMultiplier() + " " + stepDuration;
        String idQuery = "SELECT id "
                   + "FROM histogram_metadata "
                   + "WHERE report_name = '" + output + "' "
                   + "AND report_date = '" + dateString + "' "
                   + "AND duration = '" + durationString + "' "
                   + "AND title = '" + title + "' "
                   + "AND axis = '" + axisName + "' ";

        try {
            ResultSet rs = dbr.retrieve(idQuery);

            while (rs.next()) {
                id = rs.getLong(1);
            }
            rs.close();
        } catch (Exception se) {
            id = -1;
        }
        return id;
    }
    
    protected void upload(DatabaseRetriever dbr, Entry e) throws Exception {
        ResultSet rs;
        String dateString = sqlDateFormat.format(e.getStartDate());
        String durationString = ts.getStepMultiplier() + " " + stepDuration;
        long id = -1;

        if (e.cached) {
            return;
        }

        String insertStatement = "INSERT INTO histogram_metadata " +
            "(report_name, report_date, duration, title, axis) " +
            "VALUES('" + output + "', '" + dateString + "', '" +
            durationString + "', '" + title + "', '" + axisName + "');";

        dbr.update(insertStatement);
        
        id = getReportId(dbr, e);

        if (id == -1) {
            throw new Exception("Error determining id");
        }

        Iterator iter = uniqueItems.keySet().iterator();

        while (iter.hasNext()) {
            String itemName = (String) iter.next();

            dbr.update("INSERT into histograms(id, item, value) "
                     + "VALUES(" + id + ", '" + itemName + "', '"
                     + e.getRawData(itemName) + "');");
        }
    }

    public void upload(DatabaseRetriever dbr) throws Exception {
        for (int i = 0; i < entries.length; i++) {
            upload(dbr, entries[i]);
        }
        dbr.commit();
    }

    public boolean downloadCurrent(DatabaseRetriever dbr) throws Exception {
        ResultSet rs;
        String dateString = sqlDateFormat.format(entries[index].getStartDate());
        String durationString = ts.getStepMultiplier() + " " + stepDuration;
        long id = getReportId(dbr, entries[index]);

        if (id == -1) {
            return false;
        }

        rs = dbr.retrieve("histograms", new String[] { "item", "value" }, new String [] { "id = " + id });
        while (rs.next()) {
            String item = rs.getString(1);
            double data = rs.getDouble(2);
            addData(item, data);
        }
        rs.close();
        entries[index].setCached();

        return true;
    }

    private String formatDate(Date date) {
        return dateFormat.format(date);
    }

    public static class Entry {
        private Date start;
        private Date end;
        private HashMap itemMap;
        private boolean cached;
        protected double total;

        public Entry(Date start, Date end) {
            itemMap = new HashMap(5);
            this.start = start;
            this.end = end;
            this.cached = false;
            this.total = 0;
        }

        public Date getStartDate() {
            return start;
        }

        public Date getEndDate() {
            return end;
        }

        public boolean getCached() {
            return cached;
        }

        public void setCached() {
            cached = true;
        }

        public void addData(String keyName, double data) {
            ItemEntry entry = (ItemEntry) itemMap.get(keyName);
            if (entry == null) {
                entry = new ItemEntry(keyName, 0);
                itemMap.put(keyName, entry);
            }
            entry.add(data);
            total += data;
        }

        public double getData(String keyName) {
            return getRawData(keyName);
        }

        public double getRawData(String keyName) {
            ItemEntry entry = (ItemEntry) itemMap.get(keyName);
            if (entry == null) {
                return 0.0;
            } else {
                return entry.get();
            }
        }

        public double getTotal() {
            return total;
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

        public String getName() {
            return this.name;
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
