/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
package org.globus.ogsa.impl.base.multirft;

import java.rmi.RemoteException;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
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
import org.globus.ogsa.base.multirft.FileTransferJobStatusType;
import org.globus.ogsa.base.multirft.TransferStatusType;
import org.globus.ogsa.config.ContainerConfig;
import org.globus.ogsa.impl.base.multirft.TransferDbOptions;
import org.globus.ogsa.utils.MessageUtils;


/**
 *  Description of the Class
 *
 *@author     madduri
 *@created    October 17, 2003
 */
public class TransferDbAdapter {

    Connection c;
    private static Log logger = LogFactory.getLog( TransferDbAdapter.class.getName() );
    private static TransferDbAdapter dbAdapter = new TransferDbAdapter();
    private static boolean driverSetup = false;
    private static String driverName;
    /**
     *  Description of the Field
     */
    public final static String baseURI = "jdbc:apache:commons:dbcp:";
    /**
     *  Description of the Field
     */
    public final static String multiRftURI = "multiRft";
    static int connNumber;
    static GenericObjectPool connectionPool = null;
    static int def_activeConnections = 64;
    static byte def_onExhaustAction = 1;
    static long def_maxWait = 4000;
    static int def_idleConnections = 2;
    RFTOptionsType globalRFTOptions;
    int requestId;
    private boolean old = false;


    /**
     *  Constructor for the TransferDbAdapter object
     */
    private TransferDbAdapter() { }


    /**
     *  Description of the Method
     *
     *@param  dbOptions           Description of the Parameter
     *@return                     Description of the Return Value
     *@exception  RftDBException  Description of the Exception
     */
    public static TransferDbAdapter setupDBConnection( TransferDbOptions dbOptions )
             throws RftDBException {

        return setupDBConnection( dbOptions, def_activeConnections,
                def_onExhaustAction, def_maxWait,
                def_idleConnections );
    }


    /**
     *  Gets the transferDbAdapter attribute of the TransferDbAdapter class
     *
     *@return    The transferDbAdapter value
     */
    public static TransferDbAdapter getTransferDbAdapter() {
        return dbAdapter;
    }


    /**
     *  Description of the Method
     *
     *@param  dbOptions           Description of the Parameter
     *@param  activeConnections   Description of the Parameter
     *@return                     Description of the Return Value
     *@exception  RftDBException  Description of the Exception
     */
    public static TransferDbAdapter setupDBConnection( TransferDbOptions dbOptions,
            int activeConnections )
             throws RftDBException {

        return setupDBConnection( dbOptions, activeConnections,
                def_onExhaustAction, def_maxWait,
                def_idleConnections );
    }


    /**
     *  Description of the Method
     *
     *@param  dbOptions           Description of the Parameter
     *@param  activeConnections   Description of the Parameter
     *@param  onExhaustAction     Description of the Parameter
     *@param  maxWait             Description of the Parameter
     *@return                     Description of the Return Value
     *@exception  RftDBException  Description of the Exception
     */
    public static TransferDbAdapter setupDBConnection( TransferDbOptions dbOptions,
            int activeConnections,
            byte onExhaustAction,
            long maxWait )
             throws RftDBException {

        return setupDBConnection( dbOptions, activeConnections, onExhaustAction,
                maxWait, def_idleConnections );
    }


    /**
     *  Description of the Method
     *
     *@param  dbOptions           Description of the Parameter
     *@param  activeConnections   Description of the Parameter
     *@param  onExhaustAction     Description of the Parameter
     *@param  maxWait             Description of the Parameter
     *@param  idleConnections     Description of the Parameter
     *@return                     Description of the Return Value
     *@exception  RftDBException  Description of the Exception
     */
    public static TransferDbAdapter setupDBConnection( TransferDbOptions dbOptions,
            int activeConnections,
            byte onExhaustAction,
            long maxWait,
            int idleConnections )
             throws RftDBException {
        logger.debug( "Setting up database for RFT" );

        if ( !driverSetup ) {
            logger.debug(
                    "RFTDatabase: maximum active connections is " +
                    activeConnections );
            logger.debug(
                    "RFTDatabase: maximum idle connections are " +
                    idleConnections );
            driverName = dbOptions.getDriver();

            try {
                setupDriver( dbOptions.getConnectionURL(),
                        dbOptions.getUserName(), dbOptions.getPassword(),
                        activeConnections, onExhaustAction, maxWait,
                        idleConnections );
                driverSetup = true;
            } catch ( Exception e ) {
                logger.error(
                        "Unable to setup Driver with pooling " +
                        MessageUtils.toString( e ) );
                throw new RftDBException( "Unable to setup Driver with Pooling " + e );
            }
        }

        connNumber = 0;

        return dbAdapter;
    }


    /**
     *  Gets the dBConnection attribute of the TransferDbAdapter object
     *
     *@return                     The dBConnection value
     *@exception  RftDBException  Description of the Exception
     */
    private Connection getDBConnection()
             throws RftDBException {

        try {
            Class.forName( driverName );

            Connection connection = DriverManager.getConnection(
                    baseURI + multiRftURI );
            connNumber++;
            logger.debug( "Connection added connNUmber " + connNumber );

            return connection;
        } catch ( Exception e ) {
            logger.error(
                    "Unable to connect to database " +
                    MessageUtils.toString( e ) );
            throw new RftDBException( "Unable to connect to database ", e );
        }
    }


    /**
     *  Description of the Method
     *
     *@param  connectURI         Description of the Parameter
     *@param  username           Description of the Parameter
     *@param  password           Description of the Parameter
     *@param  activeConnections  Description of the Parameter
     *@param  onExhaustAction    Description of the Parameter
     *@param  maxWait            Description of the Parameter
     *@param  idleConnections    Description of the Parameter
     *@exception  Exception      Description of the Exception
     */
    private static void setupDriver( String connectURI, String username,
            String password, int activeConnections,
            byte onExhaustAction, long maxWait,
            int idleConnections )
             throws Exception {

        // Object pool which is a pool of conection
        connectionPool = new GenericObjectPool( null, activeConnections,
                onExhaustAction, maxWait,
                idleConnections );

        // ConnectionFactory that pool uses to create connectiosn
        ConnectionFactory connectionFactory = new DriverManagerConnectionFactory(
                connectURI, username,
                password );

        // PoolableConnectionFactory used for pooling functionality
        PoolableConnectionFactory poolableConnectionFactory =
                new PoolableConnectionFactory( connectionFactory,
                (ObjectPool) connectionPool, null,
                null, false, true );

        // Create and Register PoolingDriver
        PoolingDriver driver = new PoolingDriver();
        driver.registerPool( multiRftURI, connectionPool );
    }


    /*
     *  Returns the connection to the database pool
     */
    /**
     *  Description of the Method
     *
     *@param  connection          Description of the Parameter
     *@exception  RftDBException  Description of the Exception
     */
    private void returnDBConnection( Connection connection )
             throws RftDBException {

        try {
            connection.close();
            connNumber--;
            logger.debug( "Connection reduced connNUmber " + connNumber );
        } catch ( SQLException sqlExcep ) {
            logger.error(
                    "Cannot return database connection to pool" +
                    MessageUtils.toString( sqlExcep ) );
            throw new RftDBException( "Cannot return database connection to pool " +
                    sqlExcep );
        }
    }


    /**
     *  Constructor for the TransferDbAdapter object
     *
     *@param  dbOptions            Description of the Parameter
     *@exception  RemoteException  Description of the Exception
     */
    TransferDbAdapter( TransferDbOptions dbOptions )
             throws RemoteException {

        try {
            Class.forName( dbOptions.getDriver() );
            c = DriverManager.getConnection( dbOptions.getConnectionURL(),
                    dbOptions.getUserName(),
                    dbOptions.getPassword() );
        } catch ( Exception e ) {
            logger.error( "Unable to Connect to Database " + e.toString(), e );
            throw new RemoteException( MessageUtils.toString( e ) );
        }
    }


    /**
     *  Description of the Method
     *
     *@param  request              Description of the Parameter
     *@return                      Description of the Return Value
     *@exception  RemoteException  Description of the Exception
     */
    public int storeTransferRequest( TransferRequestType request )
             throws RemoteException {

        Connection c = getDBConnection();

        try {

            Statement statement = c.createStatement();
            logger.debug( "Inserting TransferRequest into the database" );

            int result = statement.executeUpdate(
                    "INSERT INTO request(concurrency) VALUES (" +
                    request.getConcurrency() + ")" );
            ResultSet rs = statement.executeQuery(
                    "SELECT COUNT(id) FROM " + "request" );

            while ( rs != null && rs.next() ) {
                this.requestId = rs.getInt( 1 );
            }

            logger.debug( "Inserted request into the database with id:" +
                    this.requestId );

            int transferStore = storeTransfers( this.requestId, request );
            returnDBConnection( c );

            return this.requestId;
        } catch ( Exception e ) {
            logger.error(
                    "Exception in inserting request in to the database" +
                    e.toString(), e );
            returnDBConnection( c );
            throw new RemoteException( MessageUtils.toString( e ) );
        }
    }


    /**
     *  Description of the Method
     *
     *@param  transfer  Description of the Parameter
     *@return           Description of the Return Value
     */
    public TransferType updateDestinationUrl( TransferType transfer ) {
        String sourceUrl = transfer.getSourceUrl();
        String fileName = sourceUrl.substring( sourceUrl.lastIndexOf( "/" ) + 1 );
        transfer.setDestinationUrl( transfer.getDestinationUrl() + fileName );
        return transfer;
    }


    /**
     *  Gets the transferCount attribute of the TransferDbAdapter object
     *
     *@return                     The transferCount value
     *@exception  RftDBException  Description of the Exception
     */
    public int getTransferCount(int requestid) throws RftDBException {
        Connection c = getDBConnection();
        int transferCount = 0;

        try {

            Statement st = c.createStatement();
            ResultSet rs = st.executeQuery(
                    "select count(*) from transfer where request_id=" 
                    + requestid);

            while ( rs != null && rs.next() ) {
                transferCount = rs.getInt( 1 );
            }
        } catch ( SQLException e ) {
            logger.error( "error in retrieving transferCount" + e.toString(), e );
            returnDBConnection( c );
            throw new RftDBException( "error in retreiving transferCount for request " );
        }

        returnDBConnection( c );
        logger.debug( "TransferCount : " + transferCount );

        return transferCount;
    }


    /**
     *  Description of the Method
     *
     *@param  transferJob         Description of the Parameter
     *@exception  RftDBException  Description of the Exception
     */
    public void storeTransferJob( TransferJob transferJob )
             throws RftDBException {
        Connection c = getDBConnection();
        try {
            Statement st = c.createStatement();
            StringBuffer query = new StringBuffer();
            query.append(
                    "INSERT into transfer(request_id,source_url,dest_url," );
            query.append( "dcau,parallel_streams,tcp_buffer_size," );
            if (!old) {
                query.append( 
                        "block_size,notpt,binary_mode,source_subject,dest_subject) VALUES(" );
            } else {
                query.append( "block_size,notpt,binary_mode) VALUES(" );
            }
            query.append( this.requestId ).
                append( ",'" ).append( transferJob.getSourceUrl() );
            query.append( "','" ).
                append( transferJob.getDestinationUrl() ).append( "'," );
            query.append( this.globalRFTOptions.isDcau() ).
                append( "," ).
                append( this.globalRFTOptions.getParallelStreams() )
                .append( "," ).
                append( this.globalRFTOptions.getTcpBufferSize() ).
                append(
                        "," ).
                append( this.globalRFTOptions.getBlockSize() ).
                append( "," ).append( this.globalRFTOptions.isNotpt() )
                .append( "," ).
                append( this.globalRFTOptions.isBinary() );
                if(!old) {
                    query.append(",'")
                    .append(this.globalRFTOptions.getSourceSubjectName())
                    .append("','")
                    .append(this.globalRFTOptions.getDestinationSubjectName())
                    .append("'");
                }
                query.append( ")" );
            logger.debug( "Query in storeTransfer: " );
            logger.debug( query.toString() );
            int returnInt = st.executeUpdate( query.toString() );
        } catch ( SQLException e ) {
            logger.error( "Unable to insert transferJob into transfer table" + e.toString(), e );
            throw new RftDBException( "Failed to insert transferJob into DB", e );
        }
        returnDBConnection( c );
    }
	


    /**
     *  Description of the Method
     *
     *@param  requestId           Description of the Parameter
     *@param  transferRequest     Description of the Parameter
     *@return                     Description of the Return Value
     *@exception  RftDBException  Description of the Exception
     */
    public int storeTransfers( int requestId,
            TransferRequestType transferRequest )
             throws RftDBException {

        Connection c = getDBConnection();
        TransferType[] transfers = transferRequest.getTransferArray();
        this.globalRFTOptions = transferRequest.getRftOptions();
        int returnInt = -1;

        for ( int i = 0; i < transfers.length; i++ ) {

            try {
                schemaCompat();

                Statement st = c.createStatement();
                TransferType transfer = transfers[i];
                if ( ( transfer.getDestinationUrl().endsWith( "/" ) ) && !( transfer.getSourceUrl().endsWith( "/" ) ) ) {
                    transfer = updateDestinationUrl( transfer );
                }
                StringBuffer query = new StringBuffer( 5000 );
                query.append(
                        "INSERT INTO transfer(request_id,source_url,dest_url," )
                        .append( "dcau,parallel_streams,tcp_buffer_size," ).append(
                        "block_size,notpt,binary_mode");
                        if(!old) {
                            query.append(",source_subject,dest_subject");
                        }
                        query.append(") VALUES (" ).append(
                        requestId ).append( ",'" ).append( transfer.getSourceUrl() )
                        .append( "','" ).append( transfer.getDestinationUrl() ).append(
                        "'," );

                RFTOptionsType rftOptions = transfer.getRftOptions();
                if ( rftOptions == null ) {
                    rftOptions = this.globalRFTOptions;
                    logger.debug( "Setting global rft options" );
                }
                query.append( rftOptions.isDcau() ).append( "," ).append( rftOptions.getParallelStreams() );
                query.append( "," ).append( rftOptions.getTcpBufferSize() ).append(
                        "," ).append( rftOptions.getBlockSize() ).append( "," ).append( rftOptions.isNotpt() );
                        query.append( "," ).append( rftOptions.isBinary());
                        if(!old) {
                            query.append(",'").
                                append(rftOptions.getSourceSubjectName()).append("','")
                                .append(rftOptions.getDestinationSubjectName())
                                .append("'");
                        }
                query.append( ")" );
                logger.debug(
                        "Query to insert into transfer table:" +
                        query.toString() );
                returnInt = st.executeUpdate( query.toString() );
            } catch ( SQLException e ) {
                logger.error(
                        "Unable to insert into Transfer table" +
                        e.toString(), e );
                returnDBConnection( c );
                throw new RftDBException( "Unable to insert into Transfer table",
                        e );
            }
        }

        returnDBConnection( c );

        return returnInt;
    }


    /**
     *  Gets the transferJobId attribute of the TransferDbAdapter object
     *
     *@param  requestId           Description of the Parameter
     *@return                     The transferJobId value
     *@exception  RftDBException  Description of the Exception
     */
    public int getTransferJobId( int requestId )
             throws RftDBException {

        Connection c = getDBConnection();
        int transferId = -1;

        try {

            Statement st = c.createStatement();
            st.setMaxRows( 1 );
            ResultSet rs = st.executeQuery(
                    "select id from transfer where request_id=" +
                    requestId );

            while ( rs != null && rs.next() ) {
                transferId = rs.getInt( 1 );
            }
        } catch ( SQLException e ) {
            logger.error( "error in retrieving transferId" + e.toString(), e );
            returnDBConnection( c );
            throw new RftDBException( "error in retreiving transferId for request: " +
                    requestId );
        }

        returnDBConnection( c );
        logger.debug( "TransferId : " + transferId );

        return transferId;
    }


    /**
     *  Gets the concurrency attribute of the TransferDbAdapter object
     *
     *@param  requestId           Description of the Parameter
     *@return                     The concurrency value
     *@exception  RftDBException  Description of the Exception
     */
    public int getConcurrency( int requestId )
             throws RftDBException {

        Connection c = getDBConnection();
        int concurrency = -1;

        try {

            Statement st = c.createStatement();
            ResultSet rs = st.executeQuery(
                    "select concurrency from request where id=" +
                    requestId );

            while ( rs != null && rs.next() ) {
                concurrency = rs.getInt( 1 );
            }
        } catch ( SQLException e ) {
            logger.error( "error in retrieving concurrency" + e.toString(), e );
            returnDBConnection( c );
            throw new RftDBException( "error in retreiving concurrency for request: " +
                    requestId );
        }

        returnDBConnection( c );
        logger.debug( "Concurrency : " + concurrency );

        return concurrency;
    }
    
    private void resetActiveTransfers(int requestId) 
    throws RftDBException,SQLException {
        schemaCompat();
        Connection c = getDBConnection();
        Statement st = c.createStatement();
        StringBuffer query = new StringBuffer(5000);
        query.append("UPDATE transfer SET status=4 where status=3");
        query.append(" and request_id=");
        query.append(requestId);
        logger.debug("Updating transfer "+query.toString()); 
        int update = st.executeUpdate(query.toString());
    }

    /**
     *  Gets the activeTransfers attribute of the TransferDbAdapter object
     *
     *@param  requestId           Description of the Parameter
     *@return                     The activeTransfers value
     *@exception  RftDBException  Description of the Exception
     */
    public Vector getActiveTransfers( int requestId , int concurrency)
             throws RftDBException {

        Connection c = getDBConnection();
        Vector activeTransfers = new Vector();
        TransferJob transferJob = null;

        try {
            resetActiveTransfers(requestId);

            Statement st = c.createStatement();
            StringBuffer query = new StringBuffer( 5000 );
            st.setMaxRows( concurrency );
            query.append( "SELECT * FROM transfer where request_id=" );
            query.append( requestId );
            query.append(" and (status=3 or status=4 )");

            logger.debug(
                    "Getting TransferJob from Database:" + query.toString() );

            ResultSet rs = st.executeQuery( query.toString() );

            while ( rs != null && rs.next() ) {

                TransferType transfer = new TransferType();
                transfer.setTransferId( rs.getInt( 1 ) );
                //TransferID
                transfer.setSourceUrl( rs.getString( 3 ) );
                transfer.setDestinationUrl( rs.getString( 4 ) );

                int status = rs.getInt( 5 );
                int attempts = rs.getInt( 6 );
                RFTOptionsType rftOptions = new RFTOptionsType();
                rftOptions.setDcau( rs.getBoolean( 7 ) );
                rftOptions.setParallelStreams( rs.getInt( 8 ) );
                rftOptions.setTcpBufferSize( rs.getInt( 9 ) );
                rftOptions.setBlockSize( rs.getInt( 10 ) );
                rftOptions.setNotpt( rs.getBoolean( 11 ) );
                rftOptions.setBinary( rs.getBoolean( 12 ) );
                logger.debug("old:" + old);
                if(!old) {
                    rftOptions.setSourceSubjectName(rs.getString(13));
                    rftOptions.setDestinationSubjectName(rs.getString(14));
                }
                transfer.setRftOptions( rftOptions );
                transferJob = new TransferJob( transfer, status, attempts );
                activeTransfers.add( transferJob );
            }
        } catch ( SQLException e ) {
            logger.error(
                    "Unable to retrieve transfers for requestid:" +
                    requestId,e);
            returnDBConnection( c );
            throw new RftDBException( "Unable to retrieve transfers for requestid",
                    e );
        }

        returnDBConnection( c );

        return activeTransfers;
    }


    /**
     *  Gets the transferJobFromRS attribute of the TransferDbAdapter object
     *
     *@param  rs                Description of the Parameter
     *@return                   The transferJobFromRS value
     *@exception  SQLException  Description of the Exception
     */
    private TransferJob getTransferJobFromRS( ResultSet rs )
             throws SQLException {
        TransferJob transferJob = null;
        while ( rs != null && rs.next() ) {

            TransferType transfer = new TransferType();
            transfer.setTransferId( rs.getInt( 1 ) );
            //TransferID
            transfer.setSourceUrl( rs.getString( 3 ) );
            transfer.setDestinationUrl( rs.getString( 4 ) );

            int status = rs.getInt( 5 );
            int attempts = rs.getInt( 6 );
            RFTOptionsType rftOptions = new RFTOptionsType();
            rftOptions.setDcau( rs.getBoolean( 7 ) );
            rftOptions.setParallelStreams( rs.getInt( 8 ) );
            rftOptions.setTcpBufferSize( rs.getInt( 9 ) );
            rftOptions.setBlockSize( rs.getInt( 10 ) );
            rftOptions.setNotpt( rs.getBoolean( 11 ) );
            rftOptions.setBinary( rs.getBoolean( 12 ) );
            transfer.setRftOptions( rftOptions );
            transferJob = new TransferJob( transfer, status, attempts );
        }
        return transferJob;
    }


    /**
     *  Gets the transferJob attribute of the TransferDbAdapter object
     *
     *@param  requestId           Description of the Parameter
     *@param  destination         Description of the Parameter
     *@param  source              Description of the Parameter
     *@return                     The transferJob value
     *@exception  RftDBException  Description of the Exception
     */
    public TransferJob getTransferJob( int requestId, String destination, String source )
             throws RftDBException {
        Connection c = getDBConnection();
        TransferJob transferJob = null;
        try {
            Statement st = c.createStatement();
            StringBuffer query = new StringBuffer( 5000 );
            query.append( "Select * from transfer where request_id=" );
            query.append( requestId );
            query.append( " AND status=4 AND source_url like '%" );
            query.append( "source%' AND dest_url like '%destination%'" );
            query.append(" order by id ");
            logger.debug( "getting transferjob " + query.toString() );
            ResultSet rs = st.executeQuery( query.toString() );
            transferJob = getTransferJobFromRS( rs );
        } catch ( SQLException e ) {
            logger.error(
                    "Unable to retrieve transfers for requestid:" +
                    requestId );
            returnDBConnection( c );
            throw new RftDBException( "Unable to retrieve transfers for requestid",
                    e );
        }
        return transferJob;
    }


    /**
     *  Gets the transferJob attribute of the TransferDbAdapter object
     *
     *@param  requestId           Description of the Parameter
     *@return                     The transferJob value
     *@exception  RftDBException  Description of the Exception
     */
    public TransferJob getTransferJob( int requestId )
             throws RftDBException {

        Connection c = getDBConnection();
        TransferJob transferJob = null;

        try {

            Statement st = c.createStatement();
            st.setMaxRows(1);
            StringBuffer query = new StringBuffer( 5000 );
            query.append( "SELECT * FROM transfer where request_id=" );
            query.append( requestId );
            query.append( " AND (status=4 OR status=1 ) order by id" );
            logger.debug(
                    "Getting TransferJob from Database:" + query.toString() );

            ResultSet rs = st.executeQuery( query.toString() );
            transferJob = getTransferJobFromRS( rs );
        } catch ( SQLException e ) {
            logger.error(
                    "Unable to retrieve transfers for requestid:" +
                    requestId );
            returnDBConnection( c );
            throw new RftDBException( "Unable to retrieve transfers for requestid",
                    e );
        }

        returnDBConnection( c );

        return transferJob;
    }

    public FileTransferJobStatusType 
        getStatus( int requestId, String sourceFile )
            throws RftDBException {
        Connection c = getDBConnection();
        FileTransferJobStatusType statusType = null;
        try {
                Statement st = c.createStatement();
                st.setMaxRows(1);
                StringBuffer query = new StringBuffer( 5000 );
                query.append("SELECT id,dest_url,status ");
                query.append("from transfer where request_id=");
                query.append(requestId);
                query.append( " and source_url='");
                query.append(sourceFile);
                query.append("'");
                logger.debug("Getting Status:" + query.toString());
                ResultSet rs = st.executeQuery( query.toString() );
                while ( rs != null && rs.next() ) {
                    statusType = new FileTransferJobStatusType();
                    statusType.setTransferId(rs.getInt(1));
                    logger.debug("status of : " + statusType.getTransferId());
                    statusType.setDestinationUrl(rs.getString(2));
                    int status = rs.getInt(3);
                    if (status==0) 
                        statusType.setStatus(TransferStatusType.Finished);
                    if (status==1) 
                        statusType.setStatus(TransferStatusType.Retrying);
                    if (status==2) 
                        statusType.setStatus(TransferStatusType.Failed);
                    if (status==3) 
                        statusType.setStatus(TransferStatusType.Active);
                    if (status==4) 
                        statusType.setStatus(TransferStatusType.Pending);
                    if (status==5) 
                        statusType.setStatus(TransferStatusType.Cancelled);
                    
                    return statusType; 
                }
        } catch (SQLException e) {
           logger.error(
                    "Unable to retrieve status for requestid:" +
                    requestId );
            returnDBConnection( c );
            throw new RftDBException( "Unable to retrieve status for requestid",
                    e );
        }

        returnDBConnection( c );

        return statusType; 
    }

    public Vector getStatusGroup( int requestId, int initial, int offset) 
        throws RftDBException {
        Connection c = getDBConnection();
        Vector statusTypes = new Vector();
        FileTransferJobStatusType statusType = null;
        try {
                Statement st = c.createStatement();
                StringBuffer query = new StringBuffer( 5000 );
                query.append("SELECT id,dest_url,status ");
                query.append("from transfer where request_id=");
                query.append(requestId);
                logger.debug("Getting Status:" + query.toString());
                ResultSet rs = st.executeQuery( query.toString() );
                while ( rs != null && rs.next() ) {
                    statusType = new FileTransferJobStatusType();
                    statusType.setTransferId(rs.getInt(1));
                    logger.debug("status of : " + statusType.getTransferId());
                    statusType.setDestinationUrl(rs.getString(2));
                    int status = rs.getInt(3);
                    if (status==0) 
                        statusType.setStatus(TransferStatusType.Finished);
                    if (status==1) 
                        statusType.setStatus(TransferStatusType.Retrying);
                    if (status==2) 
                        statusType.setStatus(TransferStatusType.Failed);
                    if (status==3) 
                        statusType.setStatus(TransferStatusType.Active);
                    if (status==4) 
                        statusType.setStatus(TransferStatusType.Pending);
                    if (status==5) 
                        statusType.setStatus(TransferStatusType.Cancelled);
                    statusTypes.add( statusType );
                }
        } catch (SQLException e) {
           logger.error(
                    "Unable to retrieve status for requestid:" +
                    requestId );
            returnDBConnection( c );
            throw new RftDBException( "Unable to retrieve status for requestid",
                    e );
        }

        returnDBConnection( c );

        return statusTypes; 
    }

                
    public Vector getTransferJob( int requestId,int concurrency)
             throws RftDBException {

        Connection c = getDBConnection();
        TransferJob transferJob = null;
        Vector transferJobs = new Vector();

        try {

            Statement st = c.createStatement();
            st.setMaxRows( concurrency );
            StringBuffer query = new StringBuffer( 5000 );
            query.append( "SELECT * FROM transfer where request_id=" );
            query.append( requestId );
            query.append(" order by id" );
            logger.debug(
                    "Getting TransferJob from Database:" + query.toString() );

            ResultSet rs = st.executeQuery( query.toString() );
            while ( rs != null && rs.next() ) {
                TransferType transfer = new TransferType();
                transfer.setTransferId( rs.getInt( 1 ) );
                //TransferID
                transfer.setSourceUrl( rs.getString( 3 ) );
                transfer.setDestinationUrl( rs.getString( 4 ) );

                int status = rs.getInt( 5 );
                int attempts = rs.getInt( 6 );
                RFTOptionsType rftOptions = new RFTOptionsType();
                rftOptions.setDcau( rs.getBoolean( 7 ) );
                rftOptions.setParallelStreams( rs.getInt( 8 ) );
                rftOptions.setTcpBufferSize( rs.getInt( 9 ) );
                rftOptions.setBlockSize( rs.getInt( 10 ) );
                rftOptions.setNotpt( rs.getBoolean( 11 ) );
                rftOptions.setBinary( rs.getBoolean( 12 ) );
                if(!old) {
                    rftOptions.setSourceSubjectName(rs.getString(13));
                    rftOptions.setDestinationSubjectName(rs.getString(14));
                }
                transfer.setRftOptions( rftOptions );
                transferJob = new TransferJob( transfer, status, attempts );
                transferJobs.add( transferJob );
            }
        } catch ( SQLException e ) {
            logger.error(
                    "Unable to retrieve transfers for requestid:" +
                    requestId );
            returnDBConnection( c );
            throw new RftDBException( "Unable to retrieve transfers for requestid",
                    e );
        }

        returnDBConnection( c );

        return transferJobs;
    }

    /**
     *  Sets the restartMarker attribute of the TransferDbAdapter object
     *
     *@param  transferJobID       The new restartMarker value
     *@param  marker              The new restartMarker value
     *@exception  RftDBException  Description of the Exception
     */
    public void setRestartMarker( int transferJobID, String marker )
             throws RftDBException {

        Connection c = getDBConnection();

        try {

            Statement st = c.createStatement();
            int update = st.executeUpdate(
                    "UPDATE restart set " + " marker='" +
                    marker + "' where transfer_id=" +
                    transferJobID );

            if ( update == 0 ) {

                int insert = st.executeUpdate(
                        "INSERT into restart(transfer_id,marker) " +
                        "VALUES(" + transferJobID + ",'" +
                        marker + "')" );
            }
        } catch ( Exception e ) {
            logger.error( "Error", e );
            returnDBConnection( c );
        }

        returnDBConnection( c );
    }


    /**
     *  Gets the proxyLocation attribute of the TransferDbAdapter object
     *
     *@param  transferJobID       Description of the Parameter
     *@return                     The proxyLocation value
     *@exception  RftDBException  Description of the Exception
     */
    public String getProxyLocation( int transferJobID )
             throws RftDBException {

        Connection c = getDBConnection();
        String proxyLocation = null;

        try {

            Statement st = c.createStatement();
            ResultSet rs = st.executeQuery(
                    "SELECT proxy_loc from proxyinfo" +
                    " where transfer_id=" + transferJobID );

            while ( rs != null && rs.next() ) {
                proxyLocation = rs.getString( 1 );
            }
        } catch ( Exception e ) {
            returnDBConnection( c );
            logger.error( "Error", e );
        }

        returnDBConnection( c );

        return proxyLocation;
    }


    /**
     *  Gets the restartMarker attribute of the TransferDbAdapter object
     *
     *@param  transferJobID       Description of the Parameter
     *@return                     The restartMarker value
     *@exception  RftDBException  Description of the Exception
     */
    public String getRestartMarker( int transferJobID )
             throws RftDBException {

        Connection c = getDBConnection();
        String marker = null;

        try {

            Statement st = c.createStatement();
            ResultSet rs = st.executeQuery(
                    "Select marker from restart " +
                    "where transfer_id=" + transferJobID );

            while ( rs.next() && rs != null ) {
                marker = rs.getString( 1 );
            }
        } catch ( Exception e ) {
            returnDBConnection( c );
            logger.error( "Error", e );
        }

        returnDBConnection( c );

        return marker;
    }


    /**
     *  Description of the Method
     *
     *@param  transferJob         Description of the Parameter
     *@exception  RftDBException  Description of the Exception
     */
    public void update( TransferJob transferJob )
             throws RftDBException {

        Connection c = getDBConnection();

        try {
            logger.debug( "In transfer dbAdapter update " +
                    transferJob.getTransferId() + " " 
                    + transferJob.getStatus() + " " +
                    transferJob.getSourceUrl() + " " + 
                    transferJob.getDestinationUrl());
            Statement st = c.createStatement();
            StringBuffer query = new StringBuffer(5000);
            query.append("UPDATE transfer SET status= ").append(
                    transferJob.getStatus()).append( ",attempts=").append(
                    transferJob.getAttempts()).append( ",dest_url='").append(
                     transferJob.getDestinationUrl()).append( "',source_url='"
                     ).append(transferJob.getSourceUrl()).append("' where id=")
                     .append (transferJob.getTransferId() );
            logger.debug("Updating transfer "+query.toString()); 
            int update = st.executeUpdate(query.toString());
            //c.commit();
            st.close();
        } catch ( Exception e ) {
            returnDBConnection( c );
            logger.error( "Error", e );
        }

        returnDBConnection( c );
    }


    /**
     *  Description of the Method
     *
     *@param  requestId           Description of the Parameter
     *@param  from                Description of the Parameter
     *@param  to                  Description of the Parameter
     *@exception  RftDBException  Description of the Exception
     */
    public void cancelTransfers( int requestId, int from, int to )
             throws RftDBException {

        Connection c = getDBConnection();

        try {

            Statement st = c.createStatement();
            Vector transferId = new Vector();

            if ( ( from == 0 ) || ( to == 0 ) ) {

                ResultSet rs = st.executeQuery(
                        "SELECT id from transfer where request_id = " +
                        requestId );

                while ( rs.next() && rs != null ) {
                    transferId.add( new Integer( rs.getInt( 1 ) ) );
                }

                for ( int i = 0; i < transferId.size(); i++ ) {

                    int update = st.executeUpdate(
                            "UPDATE transfer set status=5 where id=" +
                            (Integer) transferId.elementAt( i ) );
                }
            } else {

                for ( int i = from; i <= to; i++ ) {

                    int update = st.executeUpdate(
                            "UPDATE transfer SET status=5 where " +
                            " id = " + i + " and request_id=" +
                            requestId );
                }
            }
        } catch ( Exception e ) {
            logger.error( "Error : ", e );
            returnDBConnection( c );
        }
    }


    /**
     *  Description of the Method
     *
     *@param  transferJobID       Description of the Parameter
     *@param  location            Description of the Parameter
     *@exception  RftDBException  Description of the Exception
     */
    public void storeProxyLocation( int transferJobID, String location )
             throws RftDBException {

        Connection c = getDBConnection();

        try {
            logger.debug( "Storing proxy in: " + location );
            location = location.replace( '\\', '/' );

            Statement st = c.createStatement();
            int result = st.executeUpdate(
                    "INSERT into proxyinfo(transfer_id," +
                    "proxy_loc) VALUES(" + transferJobID +
                    ",'" + location + "')" );
            st.close();
        } catch ( Exception e ) {
            logger.error( "Error", e );
            returnDBConnection( c );
        }

        returnDBConnection( c );
    }

    private void schemaCompat() throws RftDBException {
        Connection c = getDBConnection();

        try {
            logger.debug( "Running a query to get metadata" );

            Statement st = c.createStatement();
            st.setMaxRows(1);
            ResultSet rs = st.executeQuery("Select * from transfer"); 
            ResultSetMetaData rsmd = rs.getMetaData();
            int numberOfColumns = rsmd.getColumnCount();
            logger.debug("number of columns : " + numberOfColumns);
            if( numberOfColumns == 12 ) {
                old = true; 
            } else if ( numberOfColumns == 14 ) {
                old = false;
            }
        } catch ( Exception e ) {
            logger.error( "Error", e );
            returnDBConnection( c );
        }

        returnDBConnection( c );
    }

    /**
     *  The main program for the TransferDbAdapter class
     *
     *@param  as  The command line arguments
     */
    public static void main( String[] as ) {

        try {

            String configPath = ContainerConfig.getConfig().getConfigPath();
        } catch ( Exception e ) {
            System.err.println( e );
        }
    }
}

