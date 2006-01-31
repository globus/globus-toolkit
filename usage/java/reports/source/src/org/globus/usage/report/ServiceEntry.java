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

