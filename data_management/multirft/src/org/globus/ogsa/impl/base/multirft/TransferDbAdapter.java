/*This file is licensed under the terms of the Globus Toolkit Public|License, found at http://www.globus.org/toolkit/download/license.html.*/
package org.globus.ogsa.impl.base.multirft;

import java.rmi.RemoteException;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import java.util.Vector;

import org.apache.commons.dbcp.ConnectionFactory;
import org.apache.commons.dbcp.DriverManagerConnectionFactory;
import org.apache.commons.dbcp.PoolableConnectionFactory;
import org.apache.commons.dbcp.PoolingDriver;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.pool.ObjectPool;
import org.apache.commons.pool.impl.GenericObjectPool;

import org.globus.ogsa.base.multirft.RFTOptionsType;
import org.globus.ogsa.base.multirft.TransferRequestType;
import org.globus.ogsa.base.multirft.TransferType;
import org.globus.ogsa.config.ContainerConfig;
import org.globus.ogsa.impl.base.multirft.TransferDbOptions;
import org.globus.ogsa.utils.MessageUtils;


public class TransferDbAdapter {

    Connection c;
    private static Log logger = LogFactory.getLog(TransferDbAdapter.class.getName());
    private static TransferDbAdapter dbAdapter = new TransferDbAdapter();
    private static boolean driverSetup = false;
    private static String driverName;
    final public static String baseURI = "jdbc:apache:commons:dbcp:";
    final public static String multiRftURI = "multiRft";
    static int connNumber;
    static GenericObjectPool connectionPool = null;
    static int def_activeConnections = 32;
    static byte def_onExhaustAction = 1;
    static long def_maxWait = 100;
    static int def_idleConnections = 2;

    private TransferDbAdapter() {
    }

    public static TransferDbAdapter setupDBConnection(TransferDbOptions dbOptions)
                                               throws RftDBException {

        return setupDBConnection(dbOptions, def_activeConnections, 
                                 def_onExhaustAction, def_maxWait, 
                                 def_idleConnections);
    }

    public static TransferDbAdapter getTransferDbAdapter() {
        return dbAdapter;
    }

    public static TransferDbAdapter setupDBConnection(TransferDbOptions dbOptions, 
                                                      int activeConnections)
                                               throws RftDBException {

        return setupDBConnection(dbOptions, activeConnections, 
                                 def_onExhaustAction, def_maxWait, 
                                 def_idleConnections);
    }

    public static TransferDbAdapter setupDBConnection(TransferDbOptions dbOptions, 
                                                      int activeConnections, 
                                                      byte onExhaustAction, 
                                                      long maxWait)
                                               throws RftDBException {

        return setupDBConnection(dbOptions, activeConnections, onExhaustAction, 
                                 maxWait, def_idleConnections);
    }

    public static TransferDbAdapter setupDBConnection(TransferDbOptions dbOptions, 
                                                      int activeConnections, 
                                                      byte onExhaustAction, 
                                                      long maxWait, 
                                                      int idleConnections)
                                               throws RftDBException {
        logger.debug("Setting up database for RFT");

        if (!driverSetup) {
            logger.debug(
                    "RFTDatabase: maximum active connections is " + 
                    activeConnections);
            logger.debug(
                    "RFTDatabase: maximum idle connections are " + 
                    idleConnections);
            driverName = dbOptions.getDriver();

            try {
                setupDriver(dbOptions.getConnectionURL(), 
                            dbOptions.getUserName(), dbOptions.getPassword(), 
                            activeConnections, onExhaustAction, maxWait, 
                            idleConnections);
                driverSetup = true;
            } catch (Exception e) {
                logger.error(
                        "Unable to setup Driver with pooling " + 
                        MessageUtils.toString(e));
                throw new RftDBException("Unable to setup Driver with Pooling " + e);
            }
        }

        connNumber = 0;

        return dbAdapter;
    }

    private Connection getDBConnection()
                                throws RftDBException {

        try {
            Class.forName(driverName);

            Connection connection = DriverManager.getConnection(
                                            baseURI + multiRftURI);
            connNumber++;
            logger.debug("Connection added connNUmber " + connNumber);

            return connection;
        } catch (Exception e) {
            logger.error(
                    "Unable to connect to database " + 
                    MessageUtils.toString(e));
            throw new RftDBException("Unable to connect to database ", e);
        }
    }

    private static void setupDriver(String connectURI, String username, 
                                    String password, int activeConnections, 
                                    byte onExhaustAction, long maxWait, 
                                    int idleConnections)
                             throws Exception {

        // Object pool which is a pool of conection
        connectionPool = new GenericObjectPool(null, activeConnections, 
                                               onExhaustAction, maxWait, 
                                               idleConnections);

        // ConnectionFactory that pool uses to create connectiosn
        ConnectionFactory connectionFactory = new DriverManagerConnectionFactory(
                                                      connectURI, username, 
                                                      password);

        // PoolableConnectionFactory used for pooling functionality
        PoolableConnectionFactory poolableConnectionFactory = 
                new PoolableConnectionFactory(connectionFactory, 
                                              (ObjectPool)connectionPool, null, 
                                              null, false, true);

        // Create and Register PoolingDriver
        PoolingDriver driver = new PoolingDriver();
        driver.registerPool(multiRftURI, connectionPool);
    }

    /*
      Returns the connection to the database pool
    */
    private void returnDBConnection(Connection connection)
                             throws RftDBException {

        try {
            connection.close();
            connNumber--;
            logger.debug("Connection reduced connNUmber " + connNumber);
        } catch (SQLException sqlExcep) {
            logger.error(
                    "Cannot return database connection to pool" + 
                    MessageUtils.toString(sqlExcep));
            throw new RftDBException("Cannot return database connection to pool " + 
                                     sqlExcep);
        }
    }

    TransferDbAdapter(TransferDbOptions dbOptions)
               throws RemoteException {

        try {
            Class.forName(dbOptions.getDriver());
            c = DriverManager.getConnection(dbOptions.getConnectionURL(), 
                                            dbOptions.getUserName(), 
                                            dbOptions.getPassword());
        } catch (Exception e) {
            logger.error("Unable to Connect to Database " + e.toString(), e);
            throw new RemoteException(MessageUtils.toString(e));
        }
    }

    public int storeTransferRequest(TransferRequestType request)
                             throws RemoteException {

        Connection c = getDBConnection();

        try {

            Statement statement = c.createStatement();
            int count = 0;
            logger.debug("Inserting TransferRequest into the database");

            int result = statement.executeUpdate(
                                 "INSERT INTO request(concurrency) VALUES (" + 
                                 request.getConcurrency() + ")");
            ResultSet rs = statement.executeQuery(
                                   "SELECT COUNT(id) FROM " + "request");

            while (rs != null && rs.next())
                count = rs.getInt(1);

            logger.debug("Inserted request into the database with id:" + 
                         count);

            int transferStore = storeTransfers(count, request);
            returnDBConnection(c);

            return count;
        } catch (Exception e) {
            logger.error(
                    "Exception in inserting request in to the database" + 
                    e.toString(), e);
            returnDBConnection(c);
            throw new RemoteException(MessageUtils.toString(e));
        }
    }

    public TransferType updateDestinationUrl(TransferType transfer) {
        String sourceUrl = transfer.getSourceUrl();
        String fileName= sourceUrl.substring(sourceUrl.lastIndexOf("/")+1); 
        transfer.setDestinationUrl(transfer.getDestinationUrl()+fileName);
        return transfer;
    }
    public int storeTransfers(int requestId, 
                              TransferRequestType transferRequest)
                       throws RftDBException {

        Connection c = getDBConnection();
        TransferType[] transfers = transferRequest.getTransferArray();
        RFTOptionsType globalRFTOptions = transferRequest.getRftOptions();
        int returnInt = -1;

        for (int i = 0; i < transfers.length; i++) {

            try {

                Statement st = c.createStatement();
                TransferType transfer = transfers[i];
                if((transfer.getDestinationUrl().endsWith("/")) && !(transfer.getSourceUrl().endsWith("/"))) {
                    transfer = updateDestinationUrl(transfer);
                }
                StringBuffer query = new StringBuffer(5000);
                query.append(
                        "INSERT INTO transfer(request_id,source_url,dest_url,")
                     .append("dcau,parallel_streams,tcp_buffer_size,").append(
                        "block_size,notpt,binary_mode) VALUES (").append(
                        requestId).append(",'").append(transfer.getSourceUrl())
                     .append("','").append(transfer.getDestinationUrl()).append(
                        "',");

                RFTOptionsType rftOptions = transfer.getRftOptions();
                if(rftOptions == null) {
                    rftOptions = globalRFTOptions;
                    logger.debug("Setting global rft options");
                }
                query.append(rftOptions.isDcau()).append(",").append(rftOptions.getParallelStreams())
                     .append(",").append(rftOptions.getTcpBufferSize()).append(
                        ",").append(rftOptions.getBlockSize()).append(",").append(rftOptions.isNotpt())
                     .append(",").append(rftOptions.isBinary()).append(")");
                logger.debug(
                        "Query to insert into transfer table:" + 
                        query.toString());
                returnInt = st.executeUpdate(query.toString());
            } catch (SQLException e) {
                logger.error(
                        "Unable to insert into Transfer table" + 
                        e.toString(), e);
                returnDBConnection(c);
                throw new RftDBException("Unable to insert into Transfer table", 
                                         e);
            }
        }

        returnDBConnection(c);

        return returnInt;
    }

    public int getTransferJobId(int requestId)
                         throws RftDBException {

        Connection c = getDBConnection();
        int transferId = -1;

        try {

            Statement st = c.createStatement();
            st.setMaxRows(1);
            ResultSet rs = st.executeQuery(
                                   "select id from transfer where request_id=" + 
                                   requestId );

            while (rs != null && rs.next()) {
                transferId = rs.getInt(1);
            }
        } catch (SQLException e) {
            logger.error("error in retrieving transferId" + e.toString(), e);
            returnDBConnection(c);
            throw new RftDBException("error in retreiving transferId for request: " + 
                                     requestId);
        }

        returnDBConnection(c);
        logger.debug("TransferId : " + transferId);

        return transferId;
    }

    public int getConcurrency(int requestId)
                       throws RftDBException {

        Connection c = getDBConnection();
        int concurrency = -1;

        try {

            Statement st = c.createStatement();
            ResultSet rs = st.executeQuery(
                                   "select concurrency from request where id=" + 
                                   requestId);

            while (rs != null && rs.next()) {
                concurrency = rs.getInt(1);
            }
        } catch (SQLException e) {
            logger.error("error in retrieving concurrency" + e.toString(), e);
            returnDBConnection(c);
            throw new RftDBException("error in retreiving concurrency for request: " + 
                                     requestId);
        }

        returnDBConnection(c);
        logger.debug("Concurrency : " + concurrency);

        return concurrency;
    }

    public Vector getActiveTransfers(int requestId)
                              throws RftDBException {

        Connection c = getDBConnection();
        Vector activeTransfers = new Vector();
        TransferJob transferJob = null;

        try {

            Statement st = c.createStatement();
            StringBuffer query = new StringBuffer(5000);
            query.append("SELECT * FROM transfer where request_id=");
            query.append(requestId);

            //   query.append(" AND status=3 or status=4" );
            logger.debug(
                    "Getting TransferJob from Database:" + query.toString());

            ResultSet rs = st.executeQuery(query.toString());

            while (rs != null && rs.next()) {

                TransferType transfer = new TransferType();
                transfer.setTransferId(rs.getInt(1)); //TransferID
                transfer.setSourceUrl(rs.getString(3));
                transfer.setDestinationUrl(rs.getString(4));

                int status = rs.getInt(5);
                int attempts = rs.getInt(6);
                RFTOptionsType rftOptions = new RFTOptionsType();
                rftOptions.setDcau(rs.getBoolean(7));
                rftOptions.setParallelStreams(rs.getInt(8));
                rftOptions.setTcpBufferSize(rs.getInt(9));
                rftOptions.setBlockSize(rs.getInt(10));
                rftOptions.setNotpt(rs.getBoolean(11));
                rftOptions.setBinary(rs.getBoolean(12));
               transfer.setRftOptions(rftOptions);
                transferJob = new TransferJob(transfer, status, attempts);
                activeTransfers.add(transferJob);
            }
        } catch (SQLException e) {
            logger.error(
                    "Unable to retrieve transfers for requestid:" + 
                    requestId);
            returnDBConnection(c);
            throw new RftDBException("Unable to retrieve transfers for requestid", 
                                     e);
        }

        returnDBConnection(c);

        return activeTransfers;
    }

    private TransferJob getTransferJobFromRS(ResultSet rs) 
    throws SQLException {
         TransferJob transferJob = null;
         while (rs != null && rs.next()) {

                TransferType transfer = new TransferType();
                transfer.setTransferId(rs.getInt(1)); //TransferID
                transfer.setSourceUrl(rs.getString(3));
                transfer.setDestinationUrl(rs.getString(4));

                int status = rs.getInt(5);
                int attempts = rs.getInt(6);
                RFTOptionsType rftOptions = new RFTOptionsType();
                rftOptions.setDcau(rs.getBoolean(7));
                rftOptions.setParallelStreams(rs.getInt(8));
                rftOptions.setTcpBufferSize(rs.getInt(9));
                rftOptions.setBlockSize(rs.getInt(10));
                rftOptions.setNotpt(rs.getBoolean(11));
                rftOptions.setBinary(rs.getBoolean(12));
                transfer.setRftOptions(rftOptions);
                transferJob = new TransferJob(transfer, status, attempts);
            }
        return transferJob;
    }

    public TransferJob getTransferJob(int requestId, String destination,String source)
    throws RftDBException {
        Connection c = getDBConnection();
        TransferJob transferJob = null;
        try {
            Statement st = c.createStatement();
            StringBuffer query = new StringBuffer(5000);
            query.append("Select * from transfer where request_id=");
            query.append(requestId);
            query.append(" AND status=4 AND source_url like '%");
            query.append("source%' AND dest_url like '%destination%'");
            logger.debug("getting transferjob " + query.toString());
            ResultSet rs = st.executeQuery(query.toString());
            transferJob = getTransferJobFromRS(rs);
        }catch (SQLException e) {
            logger.error(
                    "Unable to retrieve transfers for requestid:" + 
                    requestId);
            returnDBConnection(c);
            throw new RftDBException("Unable to retrieve transfers for requestid", 
                                     e);
        }
        return transferJob;
    }

            
    public TransferJob getTransferJob(int requestId)
                               throws RftDBException {

        Connection c = getDBConnection();
        TransferJob transferJob = null;

        try {

            Statement st = c.createStatement();
            StringBuffer query = new StringBuffer(5000);
            query.append("SELECT * FROM transfer where request_id=");
            query.append(requestId);
            query.append(" AND status=4 OR status=1");
            logger.debug(
                    "Getting TransferJob from Database:" + query.toString());

            ResultSet rs = st.executeQuery(query.toString());
            transferJob = getTransferJobFromRS(rs);
        } catch (SQLException e) {
            logger.error(
                    "Unable to retrieve transfers for requestid:" + 
                    requestId);
            returnDBConnection(c);
            throw new RftDBException("Unable to retrieve transfers for requestid", 
                                     e);
        }

        returnDBConnection(c);

        return transferJob;
    }

    public void setRestartMarker(int transferJobID, String marker)
                          throws RftDBException {

        Connection c = getDBConnection();

        try {

            Statement st = c.createStatement();
            int update = st.executeUpdate(
                                 "UPDATE restart set " + " marker='" + 
                                 marker + "' where transfer_id=" + 
                                 transferJobID);

            if (update == 0) {

                int insert = st.executeUpdate(
                                     "INSERT into restart(transfer_id,marker) " + 
                                     "VALUES(" + transferJobID + ",'" + 
                                     marker + "')");
            }
        } catch (Exception e) {
            logger.error("Error", e);
            returnDBConnection(c);
        }

        returnDBConnection(c);
    }

    public String getProxyLocation(int transferJobID)
                            throws RftDBException {

        Connection c = getDBConnection();
        String proxyLocation = null;

        try {

            Statement st = c.createStatement();
            ResultSet rs = st.executeQuery(
                                   "SELECT proxy_loc from proxyinfo" + 
                                   " where transfer_id=" + transferJobID);

            while (rs != null && rs.next()) {
                proxyLocation = rs.getString(1);
            }
        } catch (Exception e) {
            returnDBConnection(c);
            logger.error("Error", e);
        }

        returnDBConnection(c);

        return proxyLocation;
    }

    public String getRestartMarker(int transferJobID)
                            throws RftDBException {

        Connection c = getDBConnection();
        String marker = null;

        try {

            Statement st = c.createStatement();
            ResultSet rs = st.executeQuery(
                                   "Select marker from restart " + 
                                   "where transfer_id=" + transferJobID);

            while (rs.next() && rs != null) {
                marker = rs.getString(1);
            }
        } catch (Exception e) {
            returnDBConnection(c);
            logger.error("Error", e);
        }

        returnDBConnection(c);

        return marker;
    }

    public void update(TransferJob transferJob)
                throws RftDBException {

        Connection c = getDBConnection();

        try {
            logger.debug("In transfer dbAdapter update " + transferJob.getTransferId() + " " + transferJob.getDestinationUrl());
            Statement st = c.createStatement();
            int update = st.executeUpdate(
                                 "UPDATE transfer SET status= " + 
                                 transferJob.getStatus() + ",attempts=" + 
                                 transferJob.getAttempts() + ",dest_url='"
                                 +transferJob.getDestinationUrl()+"',source_url='"
                                 +transferJob.getSourceUrl()+"' where id=" + 
                                 transferJob.getTransferId());
            st.close();
        } catch (Exception e) {
            returnDBConnection(c);
            logger.error("Error", e);
        }

        returnDBConnection(c);
    }

    public void cancelTransfers(int requestId, int from, int to)
                         throws RftDBException {

        Connection c = getDBConnection();

        try {

            Statement st = c.createStatement();
            Vector transferId = new Vector();

            if ((from == 0) || (to == 0)) {

                ResultSet rs = st.executeQuery(
                                       "SELECT id from transfer where request_id = " + 
                                       requestId);

                while (rs.next() && rs != null) {
                    transferId.add(new Integer(rs.getInt(1)));
                }

                for (int i = 0; i < transferId.size(); i++) {

                    int update = st.executeUpdate(
                                         "UPDATE transfer set status=5 where id=" + 
                                         (Integer)transferId.elementAt(i));
                }
            } else {

                for (int i = from; i <= to; i++) {

                    int update = st.executeUpdate(
                                         "UPDATE transfer SET status=5 where " + 
                                         " id = " + i + " and request_id=" + 
                                         requestId);
                }
            }
        } catch (Exception e) {
            logger.error("Error : ", e);
            returnDBConnection(c);
        }
    }

    public void storeProxyLocation(int transferJobID, String location)
                            throws RftDBException {

        Connection c = getDBConnection();

        try {
            logger.debug("Storing proxy in: " + location);
            location = location.replace('\\', '/');

            Statement st = c.createStatement();
            int result = st.executeUpdate(
                                 "INSERT into proxyinfo(transfer_id," + 
                                 "proxy_loc) VALUES(" + transferJobID + 
                                 ",'" + location + "')");
            st.close();
        } catch (Exception e) {
            logger.error("Error", e);
            returnDBConnection(c);
        }

        returnDBConnection(c);
    }

    public static void main(String[] as) {

        try {

            String configPath = ContainerConfig.getConfig().getConfigPath();
        } catch (Exception e) {
            System.err.println(e);
        }
    }
}
