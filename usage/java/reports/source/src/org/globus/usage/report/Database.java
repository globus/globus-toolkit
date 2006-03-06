package org.globus.usage.report;

public class Database {

    private String driverClass;
    private String url;

    public Database() throws Exception {
        this.driverClass = "org.postgresql.Driver";
        this.url = "jdbc:postgresql://pgsql.mcs.anl.gov:5432/usagestats?user=allcock&password=bigio";

        Class.forName(this.driverClass);
    }

    public String getURL() {
        return this.url;
    }
}

