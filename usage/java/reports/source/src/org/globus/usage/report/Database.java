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

import java.io.InputStream;
import java.util.Properties;

public class Database {

    private String driverClass;
    private String url;

    public Database() throws Exception {
        this("etc/globus_usage_reports/db.properties");
    }

    public Database(String props) throws Exception {

        InputStream in = 
            getClass().getClassLoader().getResourceAsStream(props);
        if (in == null) {
            throw new Exception("Unable to load resource");
        }
        
        Properties properties = new Properties();
        try {
            properties.load(in);
        } finally {
            try {
                in.close();
            } catch (Exception e) {}
        }

        this.driverClass = properties.getProperty("db.driver");
        this.url = properties.getProperty("db.url");

        Class.forName(this.driverClass);
    }

    public String getURL() {
        return this.url;
    }
}

