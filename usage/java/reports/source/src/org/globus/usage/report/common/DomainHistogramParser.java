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
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;

public class DomainHistogramParser extends HistogramParser {
    static HashMap<String, IPEntry> IPEntryMap = new HashMap<String, IPEntry>();

    public DomainHistogramParser(String t, String o, String a, TimeStep ts) {
        super(t, o, a, ts);
    }

    public void addData(String item, double data) {
        IPEntry ie = IPEntryMap.get(item);
        if (ie == null) {
            ie = IPEntry.getIPEntry(item);
            IPEntryMap.put(item, ie);
        }
        super.addData(ie.getDomain(), data);
    }
}
