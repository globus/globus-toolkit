/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
package org.globus.ogsa.impl.base.multirft;

public class TransferDbOptions {

    String driver;
    String connectionURL;
    String userName;
    String password;

    TransferDbOptions(String driver, String connectionURL, String userName, 
                      String password) {
        this.driver = driver;
        this.connectionURL = connectionURL;
        this.userName = userName;
        this.password = password;
    }

    public void setDriver(String driver) {
        this.driver = driver;
    }

    public String getDriver() {

        return this.driver;
    }

    public String getConnectionURL() {

        return this.connectionURL;
    }

    public void setConnectionURL(String connectionURL) {
        this.connectionURL = connectionURL;
    }

    public String getUserName() {

        return this.userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {

        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
