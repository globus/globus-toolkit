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
import java.sql.SQLException;

import java.util.Date;
import java.text.SimpleDateFormat;

public class DatabaseRetriever {

    private Database db;

    private Connection con;

    private Statement stmt;

    public DatabaseRetriever() {
        try {
            this.db = new Database();
            this.con = DriverManager.getConnection(db.getURL());
        } catch (Exception e) {
            System.err.println("Error Configuring Database: " + e.getMessage());
        }
    }

    public DatabaseRetriever(String databaseproperties) {
        try {
            db = new Database(databaseproperties);
            con = DriverManager.getConnection(db.getURL());
        } catch (Exception e) {
            System.err.println("Error Configuring Database: " + e.getMessage());
        }
    }

    public ResultSet retrieve(String packetType, String[] columns,
            Date startDate, Date endDate) {
        return retrieve(packetType, columns, new String[0], startDate, endDate);
    }

    public ResultSet retrieve(String packetType, String[] columns,
            String startDateString, String endDateString) {
        return retrieve(packetType, columns, new String[0], startDateString,
                endDateString);
    }

    public ResultSet retrieve(String packetType, String[] columns,
            String[] conditions, Date startDate, Date endDate) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        String startDateString = dateFormat.format(startDate);
        String endDateString = dateFormat.format(endDate);
        return retrieve(packetType, columns, conditions, startDateString,
                endDateString);
    }

    public ResultSet retrieve(String packetType, String[] columns,
            String[] conditions, String startDateString, String endDateString) {
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
        try {
            stmt = con.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            return rs;
        } catch (SQLException e) {
            System.err.println("SQLException: " + e.getMessage());
            return null;
        }
    }

    public void close() throws Exception {
        try {
            if (con != null) {
                con.close();
            }
            if (stmt != null) {
                stmt.close();
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }
}
