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

import java.sql.DriverManager;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;
import java.util.Date;
import java.text.SimpleDateFormat;

public class DatabaseRetriever {

    private Database db;

    private Connection con;

    private Statement stmt;

    public DatabaseRetriever() throws Exception {
        this.db = new Database();
        this.con = DriverManager.getConnection(db.getURL());
    }

    public DatabaseRetriever(String databaseproperties) throws Exception {
        this.db = new Database(databaseproperties);
        this.con = DriverManager.getConnection(db.getURL());
    }

    public ResultSet retrieve(String packetType,
                              String[] columns,
                              Date startDate,
                              Date endDate) throws Exception {
        return retrieve(packetType, columns, new String[0], startDate, endDate);
    }

    public ResultSet retrieve(String packetType,
                              String[] columns,
                              String startDateString,
                              String endDateString) throws Exception {
        return retrieve(packetType, columns, new String[0], startDateString,
                endDateString);
    }

    public ResultSet retrieve(String packetType,
                              String[] columns,
                              String[] conditions,
                              Date startDate,
                              Date endDate) throws Exception {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        String startDateString = dateFormat.format(startDate);
        String endDateString = dateFormat.format(endDate);
        return retrieve(packetType, columns, conditions, startDateString,
                endDateString);
    }

    public ResultSet retrieve(String packetType,
                              String[] columns,
                              String[] conditions,
                              String startDateString,
                              String endDateString) throws Exception {
        String query = "select ";

        for (int n = 0; n < columns.length - 1; n++) {
            query = query + columns[n] + ",";
        }

        query = query + columns[columns.length - 1] + " from " + packetType
                + " where ";
        for (int n = 0; n < conditions.length; n++) {
            query = query + conditions[n] + " and ";
        }

        query = query + "send_time >= '" + startDateString
                + "' and send_time < '" + endDateString + "'";

        this.stmt = this.con.createStatement();
        return this.stmt.executeQuery(query);
    }

    public void close() {
        if (this.stmt != null) {
            try {
                this.stmt.close();
            } catch (Exception e) {
            }
        }
        if (this.con != null) {
            try {
                this.con.close();
            } catch (Exception e) {
            }
        }
    }

}
