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
package org.globus.usage.report;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

public class ServiceEntry extends IPTable {

    int standalone;
    int servlet;
    int other;
    
    public void standalone() {
        standalone++;
    }

    public void servlet() {
        servlet++;
    }

    public void other() {
        other++;
    }

    public int getStandaloneCount() {
        return standalone;
    }

    public int getServletCount() {
        return servlet;
    }

    public int getOtherCount() {
        return other;
    }

}

