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

