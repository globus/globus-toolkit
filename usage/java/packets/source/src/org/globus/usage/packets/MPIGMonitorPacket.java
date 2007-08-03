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

package org.globus.usage.packets;

import java.net.InetAddress;
import java.sql.Timestamp;
import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Date;
import java.util.Calendar;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class MPIGMonitorPacket extends CStylePacket {

    private String mpichver;
    private String hostname;
    private int nprocs;
    private long nbytes;
    private long nbytesv;
    private int test;
    private String fnmap;
    private Timestamp startstamp;
    private Timestamp endstamp;    
    /*Code is 8, version is 0*/

    public String getMpichVer() {
        return mpichver;
    }

    public void setMpichVer(String ver) {
        mpichver = ver;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public int getNprocs() {
        return nprocs;
    }

    public void setNprocs(int nprocs) {
        this.nprocs = nprocs;
    }

    public long getNbytes() {
        return nbytes;
    }

    public void setNbytes(long nbytes) {
        this.nbytes = nbytes;
    }

    public long getNbytesv() {
        return nbytesv;
    }

    public void setNbytesv(long nbytesv) {
        this.nbytesv = nbytesv;
    }

    public int getTest() {
        return test;
    }

    public void setTest(int test) {
        this.test = test;
    }

    public String getFnmap() {
        return fnmap;
    }

    public void setFnmap(String fnmap) {
        this.fnmap = fnmap;
    }

    public Timestamp getStartTimestamp() {
        return startstamp;
    }

    public void setStartTimestamp(Timestamp startstamp) {
        this.startstamp = startstamp;
    }

    public Timestamp getEndTimestamp() {
        return endstamp;
    }

    public void setEndTimestamp(Timestamp endstamp) {
        this.endstamp = endstamp;    
    }

    public void unpackCustomFields(CustomByteBuffer buf) {
        String starttime, endtime;
        long startsec, endsec;         
        int startusec, endusec;        
        super.unpackCustomFields(buf);
        PacketFieldParser parser = parseTextSection(buf);

        hostname = parser.getString("HOSTNAME");
        mpichver = parser.getString("MPICHVER");

        starttime = parser.getString("START");
        startsec = Long.parseLong(starttime.substring(0, starttime.indexOf('.')));
        startusec = Integer.parseInt(starttime.substring(starttime.indexOf('.')+1));
        startstamp = new Timestamp(startsec * 1000);
        startstamp.setNanos(startusec * 1000);

        endtime = parser.getString("END");
        endsec = Long.parseLong(endtime.substring(0, endtime.indexOf('.')));
        endusec = Integer.parseInt(endtime.substring(endtime.indexOf('.')+1));
        endstamp = new Timestamp(endsec * 1000);
        endstamp.setNanos(endusec * 1000);

        nprocs = parser.getInt("NPROCS");
        nbytes = parser.getLong("NBYTES");
        nbytesv = parser.getLong("NBYTESV");
        test = parser.getInt("TEST");
        fnmap = parser.getString("FNMAP");
    }
}
