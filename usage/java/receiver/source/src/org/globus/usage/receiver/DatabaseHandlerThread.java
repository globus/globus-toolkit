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

package org.globus.usage.receiver;

import java.io.IOException;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.usage.receiver.handlers.DefaultPacketHandler;
import org.globus.usage.receiver.handlers.PacketHandler;

import java.sql.DriverManager;

import org.apache.commons.pool.ObjectPool;
import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.commons.dbcp.ConnectionFactory;
import org.apache.commons.dbcp.PoolingDriver;
import org.apache.commons.dbcp.PoolableConnectionFactory;
import org.apache.commons.dbcp.DriverManagerConnectionFactory;


public class DatabaseHandlerThread extends HandlerThread {
    public static final String dbPoolName = "jdbc:apache:commons:dbcp:usagestats";
    private static final String POOL_NAME = "usagestats";
    private static Log log = LogFactory.getLog(DatabaseHandlerThread.class);

    public DatabaseHandlerThread(RingBuffer ring, Properties props) {
        super(ring, props);

        String driverClass = props.getProperty("database-driver");
        String dburl = props.getProperty("database-url");
        String table = props.getProperty("default-table");
         
	try {
            Class theClass = null;

            try {
                theClass = Class.forName(driverClass, true,
                        Thread.currentThread().getContextClassLoader());
            } catch (ClassNotFoundException e) {
                theClass = Class.forName(driverClass.trim());
            }
	    setUpDatabaseConnectionPool(dburl, props);
	    theDefaultHandler = new DefaultPacketHandler(dbPoolName, table);
	} catch (Exception e) {
	    log.error("Can't start handler thread: " + e.getMessage());
	    stillGood = false;
	}
    }

    private void setUpDatabaseConnectionPool(String dburl, Properties props) 
        throws Exception {
	/*Set up database connection pool:  all handlers which need a 
	  database connection (which, so far, is all handlers) can take
	  connections from this pool.*/
        
        String dbuser = props.getProperty("database-user");
        String dbpwd = props.getProperty("database-pwd");
        String dbValidationQuery = props.getProperty("database-validation-query");

	GenericObjectPool connectionPool = new GenericObjectPool(null);
	ConnectionFactory connectionFactory = new DriverManagerConnectionFactory(dburl, dbuser, dbpwd);
	PoolableConnectionFactory poolableConnectionFactory = 
            new PoolableConnectionFactory(connectionFactory, connectionPool, null, 
                                          dbValidationQuery, false, true);
	PoolingDriver driver = new PoolingDriver();
	driver.registerPool(POOL_NAME, connectionPool);
    }

    /*This thread waits on the RingBuffer; when packets come in, it starts
      reading them out and letting the handlers have them.*/
    public void run() {
        super.run();

        closeDatabaseConnectionPool();
    }

    protected void closeDatabaseConnectionPool() {
        log.info("Closing database connection pool");
	try {
	    PoolingDriver driver = 
                (PoolingDriver)DriverManager.getDriver("jdbc:apache:commons:dbcp:");
	    driver.closePool(POOL_NAME);
	} catch(Exception e) {
	    log.warn(e.getMessage());
	}
    }
}
