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

import java.util.Date;

public class PercentageHistogramParser extends HistogramParser {
    public PercentageHistogramParser(String t, String o, String a, TimeStep ts) {
        super(t, o, a, ts);
    }

    public void nextEntry() {
        nextEntry(new PercentageEntry(ts.getTime(), ts.stepTime()));
    }

    public static class PercentageEntry extends Entry {
        private double total;

        public PercentageEntry(Date start, Date end) {
            super(start, end);
            total = 0.0;
        }

        public void addData(String keyName, double data) {
            super.addData(keyName, data);
            total += data;
        }

        public double getData(String keyName) {
            return 100.0 * super.getData(keyName) / total;
        }
    }
}
