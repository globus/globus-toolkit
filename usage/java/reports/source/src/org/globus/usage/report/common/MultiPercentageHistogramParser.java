/*
 * Copyright 1999-2008 University of Chicago
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

import java.io.PrintStream;
import java.sql.ResultSet;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;

/**
 * PercentageHistogramParser where each entry value is considered an attribute
 * which some percentage of the data contain. As such, for each timestep, the
 * total value is not necessarily the sum of data points, which may each
 * contain multiple attributes.
 */
public class MultiPercentageHistogramParser
extends PercentageHistogramParser {
    private final static String TOTAL_DB_ITEM = "__TOTAL__";
    private double total;
    private PercentageEntry currentEntry;

    public MultiPercentageHistogramParser(String t, String o, String a, TimeStep ts) {
        super(t, o, a, ts);
        total = 0;
        currentEntry = null;
    }

    public boolean downloadCurrent(DatabaseRetriever dbr) {
        ResultSet rs = null;
        long id = getReportId(dbr, currentEntry);
        double tmp = 0;

        if (id == -1) {
            return false;
        }

        try {
            rs = dbr.retrieve(
                    "histograms", new String[] { "item", "value" },
                    new String [] { "id = " + id });

            while (rs.next()) {
                String item = rs.getString(1);
                double data = rs.getDouble(2);

                if (item.equals(TOTAL_DB_ITEM)) {
                    tmp = data;
                } else {
                    addData(item, data);
                }
            }
            currentEntry.setCached();
            setTotal(tmp);
            rs.close();
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    protected void upload(DatabaseRetriever dbr, Entry e) throws Exception {
        if (! e.getCached()) {
            super.upload(dbr, e);
            long id = getReportId(dbr, e);

            dbr.update("INSERT into histograms(id, item, value) "
                     + "VALUES(" + id + ", '" + TOTAL_DB_ITEM + "', '"
                     + ((PercentageEntry) e).getTotal() + "');");
        }
    }

    public void nextEntry() {
        currentEntry = new PercentageEntry(ts.getTime(), ts.stepTime());
        nextEntry(currentEntry);
    }

    public void setTotal(double total) {
        currentEntry.setTotal(total);
        this.total += total;
    }

    protected double getTotal() {
        return total;
    }
}
