/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
package org.globus.ogsa.impl.base.multirft;

import java.io.BufferedReader;
import java.io.IOException;

import java.net.MalformedURLException;

import java.rmi.RemoteException;

import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import javax.security.auth.Subject;

import javax.xml.namespace.QName;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.axis.gsi.GSIConstants;
import org.globus.ftp.exception.ServerException;
import org.globus.gsi.jaas.JaasGssUtil;


import org.globus.ogsa.GridContext;
import org.globus.ogsa.GridServiceException;
import org.globus.ogsa.ServiceData;
import org.globus.ogsa.ServiceProperties;
import org.globus.ogsa.base.multirft.*;
import org.globus.ogsa.impl.base.multirft.util.URLExpander;
import org.globus.ogsa.impl.ogsi.GridServiceImpl;
import org.globus.ogsa.impl.security.SecurityManager;
import org.globus.ogsa.impl.security.authentication.Constants;
import org.globus.ogsa.impl.security.authentication.SecureServicePropertiesHelper;
import org.globus.ogsa.impl.security.authorization.SelfAuthorization;
import org.globus.ogsa.utils.MessageUtils;
import org.globus.util.GlobusURL;
import org.globus.util.Util;




import org.ietf.jgss.GSSCredential;


/**
 *  Description of the Class
 *
 *@author     madduri
 *@created    September 17, 2003
 */
public class RftImpl
extends GridServiceImpl {
    
    static Log logger = LogFactory.getLog(RftImpl.class.getName());
    boolean connectionPoolingEnabled = false; //no connection pooling
    private static Object criticalSection = new Object();
    String configPath;
    TransferRequestType transferRequest;
    TransferRequestElement transferRequestElement;
    private Map notifyProps;
    int concurrency;
    int maxAttempts = 10;
    TransferDbAdapter dbAdapter;
    TransferDbOptions dbOptions;
    ServiceData transferProgressData;
    ServiceData restartMarkerServiceData;
    ServiceData singleFileTransferStatusSDE;
    ServiceData gridFTPRestartMarkerSD;
    ServiceData gridFTPPerfMarkerSD;
    ServiceData versionSD;
    ServiceData overallStatus;
    FileTransferProgressType transferProgress;
    FileTransferRestartMarker restartMarkerDataType;
    FileTransferStatusElement fileTransferStatusElement;
    GridFTPRestartMarkerElement gridFTPRestartMarkerSDE;
    GridFTPPerfMarkerElement gridFTPPerfMarkerSDE;
    OverallStatus overallStatusSDE;
    Version version;
    int requestId = -1;
    private int persistentRequestId = 0;
    private int requestId_ = 0;
    private int transferJobId_ = 0;
    private boolean check = false;
    // check to update transferids of Status SDEs
    Vector activeTransferThreads;
    Vector transferClients;
    RFTOptionsType globalRFTOptionsType;
    private String proxyLocation = null;
    TransfersActive activeTransfers = new TransfersActive();
    TransfersFailed failedTransfers = new TransfersFailed();
    TransfersFinished finishedTransfers = new TransfersFinished();
    TransfersPending pendingTransfers = new TransfersPending();
    TransfersRestarted restartedTransfers = new TransfersRestarted();
    TransfersCancelled cancelledTransfers = new TransfersCancelled();
    int numberActive,numberFailed,numberPending,
        numberFinished,numberRestarted,numberCancelled;
    int transferCount = 0;
    
    /**
     *  Constructor for the RftImpl object
     */
    public RftImpl() {
        super( "MultifileRFTService" );
        this.transferRequest = null;
    }
    
    
    /**
     *  Constructor for the RftImpl object
     *
     *@param  transferRequest  Description of the Parameter
     */
    public RftImpl( TransferRequestType transferRequest ) {
        super( "MultifileRFTService" );
        
        String name = "MultifileRFTService";
        
        this.transferRequest = transferRequest;
        this.globalRFTOptionsType = transferRequest.getRftOptions();
        
        if ( transferRequest == null ) {
            logger.debug( "transfer request is null" );
        }
    }
    
    
    /**
     *  start()
     *  delegation takes place here
     *@return                   requestId
     *@throws  RemoteException
     */
    public int start()
    throws RemoteException {
        
        Subject subject = SecurityManager.getManager().setServiceOwnerFromContext(
        this );
        GSSCredential cred = JaasGssUtil.getCredential( subject );
        
        if ( cred == null ) {
            throw new RemoteException( "Delegation not performed" );
        }
        
        try {
            
            String path = TransferClient.saveCredential( cred );
            Util.setFilePermissions( path, 600 );
            dbAdapter.storeProxyLocation( requestId, path );
            this.proxyLocation = path;
            int temp = 0;
            Vector initialTransfers = dbAdapter.getTransferJob( requestId,
                concurrency );
            if (initialTransfers.size() > 0 ) {
                for(int i=0;i<initialTransfers.size();i++) {
                    TransferJob transferJob = (TransferJob) 
                       initialTransfers.elementAt(i);
                    processURLs( transferJob );
                    dbAdapter.update( transferJob );
                    TransferThread transferThread = new TransferThread 
                        (transferJob);
                    transferThread.start();
                    transferJob.setStatus(TransferJob.STATUS_ACTIVE);
                    statusChanged(transferJob);
                    dbAdapter.update(transferJob);
                    activeTransferThreads.add( transferThread );
                }
            } else {
                throw new RemoteException("Invalid value for concurrency" );
            }
        } catch ( Exception e ) {
            logger.error( "Error in start " + e.toString(), e );
            throw new RemoteException( MessageUtils.toString( e ) );
        }
        
        return requestId;
    }
    
    
    /**
     * cancel the transfers  
     * only transfers that were not started 
     * can be cancelled
     *@param  requestId         DOCUMENT ME!
     *@param  fromId            DOCUMENT ME!
     *@param  toId              DOCUMENT ME!
     *@throws  RemoteException  DOCUMENT ME!
     */
    public void cancel( int requestId, int fromId, int toId )
    throws RemoteException {
        logger.debug( "Cancelling transfers of the request: " + requestId );
        logger.debug( "from id: " + fromId + "to id: " + toId );
        dbAdapter.cancelTransfers( requestId, fromId, toId );
        cancelActiveTransfers( fromId, toId );
    }
    
    public FileTransferJobStatusType getStatus( String sourceFileName) 
    throws RemoteException {
        logger.debug(" Getting Status for : " + sourceFileName);
        FileTransferJobStatusType statusType = 
            dbAdapter.getStatus( this.requestId, sourceFileName );
        if (statusType != null) {
            return statusType;
        }
        else {
            throw new RemoteException("GetStatus returned null");
        }
    }

    public FileTransferJobStatusType[] getStatusGroup( 
            int initial, int offset ) throws RemoteException {
        logger.debug(" Getting Status from : " + initial );
        logger.debug(" To : " + offset );
        Vector statusTypes =
            dbAdapter.getStatusGroup( this.requestId, initial, offset ); 
        int size = statusTypes.size();
        FileTransferJobStatusType[] statusTypesArray = 
            new FileTransferJobStatusType[ size ];
        for ( int i = 0;i < size; i++ ) {
            statusTypesArray[i] = (FileTransferJobStatusType) 
                statusTypes.remove(i);
        }
        if ( statusTypes != null ) { 
            return statusTypesArray;
        } else {
            throw new RemoteException("getStatusGroup returned null");
        }
    }
    /**
     *
     *@param  fromId           
     *@param  toId            
     *@throws  RftDBException  
     */
    public void cancelActiveTransfers( int fromId, int toId )
    throws RftDBException {
        
        for ( int i = fromId; i <= toId; i++ ) {
            
            TransferThread tempTransferThread = (TransferThread) activeTransferThreads.elementAt(
            i );
            tempTransferThread.killThread();
        }
    }
    
    
    public TransferJob processURLs( TransferJob transferJob ) {
        logger.debug( "checking to see if destination URL is a directory" );
        String destinationURL = transferJob.getDestinationUrl();
        String sourceURL = transferJob.getSourceUrl();
        
        if ( ( destinationURL.endsWith( "/" ) ) && !( sourceURL.endsWith( "/" ) ) ) {
            logger.debug( "The destinationURL : " + destinationURL +
            " appears to be a directory" );
            String fileName = extractFileName( sourceURL );
            destinationURL = destinationURL + fileName;
            transferJob.setDestinationUrl( destinationURL );
            try {
                dbAdapter.update( transferJob );
            } catch ( RftDBException rdb ) {
                logger.debug( "Error processing urls" );
            }
            //change the destUrl by appending filename to it
        }
        return transferJob;
    }
    
     /** extracts the file name from the url
     * @param sourceURL
     * @return
     */
    public String extractFileName( String sourceURL ) {
        return sourceURL.substring( sourceURL.lastIndexOf( "/" ) + 1 );
    }
    
    private synchronized void setOverallStatusSDE( int transferStatus){
        logger.debug("Transferstatus in set:"+transferStatus);
        logger.debug(this.numberFinished+" " + this.numberActive +
            " " + this.numberPending + " " + this.numberFailed);
        if( transferStatus == TransferJob.STATUS_FINISHED ) {
            this.numberFinished++;
            this.numberActive--;
        }
        if ( transferStatus == TransferJob.STATUS_FAILED ) {
            this.numberFailed++;
            this.numberActive--;
        }
        if( transferStatus == TransferJob.STATUS_ACTIVE) {
            this.numberActive++;
            this.numberPending--;
        }
        if( transferStatus == TransferJob.STATUS_RETRYING) {
            this.numberRestarted++;
            this.numberActive--;
        }
        this.activeTransfers.setNumberActive(this.numberActive);
        this.failedTransfers.setNumberFailed(this.numberFailed);
        this.finishedTransfers.setNumberFinished(this.numberFinished);
        this.pendingTransfers.setNumberPending(this.numberPending);
        this.restartedTransfers.setNumberRestarted(this.numberRestarted);
        
        this.overallStatusSDE.setTransfersActive(this.activeTransfers);
        this.overallStatusSDE.setTransfersFinished(this.finishedTransfers);
        this.overallStatusSDE.setTransfersPending(this.pendingTransfers);
        this.overallStatusSDE.setTransfersFailed(this.failedTransfers);
        this.overallStatusSDE.setTransfersRestarted(this.restartedTransfers);
        this.overallStatus.setValue(this.overallStatusSDE);
        this.overallStatus.notifyChange();
    }
    
    private void setSDE() throws GridServiceException {
        transferProgress = new FileTransferProgressType();
        restartMarkerDataType = new FileTransferRestartMarker();
        fileTransferStatusElement = new FileTransferStatusElement();
        gridFTPRestartMarkerSDE = new GridFTPRestartMarkerElement();
        gridFTPPerfMarkerSDE = new GridFTPPerfMarkerElement();
        version = new Version();
        this.overallStatusSDE = new OverallStatus();
        this.transferProgressData = this.serviceData.create(
        new QName("FileTransferProgress"));
        this.singleFileTransferStatusSDE = this.serviceData.create(
        new QName("SingleFileTransferStatus"));
        this.restartMarkerServiceData = this.serviceData.create(
        new QName("FileTransferRestartMarker"));
        this.gridFTPRestartMarkerSD = this.serviceData.create(
        new QName("GridFTPRestartMarker"));
        this.gridFTPPerfMarkerSD = this.serviceData.create(
        new QName("GridFTPPerfMarker"));
        this.versionSD = this.serviceData.create(
        new QName("MultiRFTVersion"));
        this.version.setVersion("1.1");
        
        this.versionSD.setValue(this.version);
        this.serviceData.add(this.versionSD);
        this.overallStatus = this.serviceData.create( new QName("OverallStatus"));
        this.serviceData.add(this.overallStatus);
        int progressInt = 0;
        this.transferProgress.setPercentComplete( progressInt );
        this.transferProgressData.setValue( transferProgress );
        this.serviceData.add( transferProgressData );
        this.restartMarkerDataType.setRestartMarkerRange( progressInt );
        this.restartMarkerServiceData.setValue( restartMarkerDataType );
        this.serviceData.add( restartMarkerServiceData );
        
        FileTransferJobStatusType statusType = new FileTransferJobStatusType();
        statusType.setTransferId( -1 );
        statusType.setDestinationUrl( "destURLPlaceHolder" );
        statusType.setStatus( null );
        fileTransferStatusElement.setRequestStatus( statusType );
        this.singleFileTransferStatusSDE.setValue(
        fileTransferStatusElement );
        this.serviceData.add( singleFileTransferStatusSDE );
        gridFTPRestartMarkerSDE.setGridFTPRestartMarker( new GridFTPRestartMarkerType() );
        this.gridFTPRestartMarkerSD.setValue( this.gridFTPRestartMarkerSDE );
        this.serviceData.add( this.gridFTPRestartMarkerSD );
        gridFTPPerfMarkerSDE.setGridFTPPerfMarker( new GridFTPPerfMarkerType() );
        this.gridFTPPerfMarkerSD.setValue( this.gridFTPPerfMarkerSDE );
        this.serviceData.add( this.gridFTPPerfMarkerSD );
    }
    
    private void recoverRequest() throws Exception {
        String proxyLocation = dbAdapter.getProxyLocation(
        this.persistentRequestId );
        this.proxyLocation = proxyLocation;
        GSSCredential credential = TransferClient.loadCredential(
        proxyLocation );
        setNotifyProps( credential, Constants.ENCRYPTION );
        
        Vector recoveredTransferJobs = dbAdapter.getActiveTransfers(
        persistentRequestId, this.concurrency );
        int tempSize = recoveredTransferJobs.size();
        logger.debug("temp size: " + tempSize);
        //transfers = new TransferType[tempSize];
        
       /* for ( int i = 0; i < tempSize; i++ ) {
            
            TransferJob transferJob = (TransferJob) recoveredTransferJobs.elementAt(
            i );
            
            //converting recovered transfers to transfer types
            transfers[i] = new TransferType();
            transfers[i].setSourceUrl( transferJob.getSourceUrl() );
            transfers[i].setDestinationUrl( transferJob.getDestinationUrl() );
            transfers[i].setRftOptions( transferJob.getRftOptions() );
        }*/
        
        int concurrency_ = dbAdapter.getConcurrency(
        this.persistentRequestId );
        this.globalRFTOptionsType = null;
        logger.debug(
        "Concurrency of recovered request: " + concurrency_ );
        if ( tempSize >= 1 ) {
            for ( int i = 0; i < concurrency_; i++ ) {

                TransferJob transferJob = (TransferJob)
                    recoveredTransferJobs.elementAt( i );
                int tempStatus = transferJob.getStatus();
            
                if ( ( tempStatus == TransferJob.STATUS_ACTIVE ) ||
                        ( tempStatus == TransferJob.STATUS_PENDING ) ||
                        ( tempStatus == TransferJob.STATUS_EXPANDING ) ) {
                
                    TransferThread transferThread = new TransferThread(
                            transferJob );
                    System.out.println( "Starting recovered transfer jobs "+ i );
                    transferThread.start();
                    statusChanged(transferJob);
                }
            }
        } else {
            closeAll();
        }
    }
    /**
     *@param  messageContext       
     *@throws  GridServiceException 
     */
    public void postCreate( GridContext messageContext )
    throws GridServiceException {
        try {
            super.postCreate( messageContext );
            ServiceProperties factoryProperties = (ServiceProperties) getProperty(
            ServiceProperties.FACTORY );
            //turn on connection pooling if requested
            String connectionPoolingValue
            = (String) factoryProperties.getProperty("connection.pooling");
            if( (connectionPoolingValue != null)
            && (connectionPoolingValue.equalsIgnoreCase("true"))) {
                this.connectionPoolingEnabled = true;
            }
            setSDE();
            
            String persistentRequestIdString = (String) getPersistentProperty(
            "requestId" );
            String temp = (String) factoryProperties.getProperty( "maxAttempts" );
            this.maxAttempts = Integer.parseInt( temp );
            String jdbcDriver = (String) factoryProperties.getProperty(
            "JdbcDriver" );
            String connectionURL = (String) factoryProperties.getProperty(
            "connectionURL" );
            String userName = (String) factoryProperties.getProperty(
            "dbusername" );
            String password = (String) factoryProperties.getProperty( "password" );
            dbOptions = new TransferDbOptions( jdbcDriver, connectionURL,
            userName, password );
            dbAdapter = TransferDbAdapter.setupDBConnection( dbOptions );
            activeTransferThreads = new Vector();
            transferClients = new Vector();
            
            if ( persistentRequestIdString != null ) {
                logger.debug(
                "recovering transfer request: " +
                persistentRequestIdString );
                this.persistentRequestId = Integer.parseInt(
                persistentRequestIdString );
                this.requestId = this.persistentRequestId;
                this.concurrency = 
                    this.dbAdapter.getConcurrency( this.requestId);
                recoverRequest();
                
            } else {
                SecurityManager manager = SecurityManager.getManager();
                
                GSSCredential cred = SecureServicePropertiesHelper.getCredential(
                this );
                //transfers = this.transferRequest.getTransferArray();
                this.concurrency = transferRequest.getConcurrency();
                requestId = dbAdapter.storeTransferRequest(
                this.transferRequest );
                setPersistentProperty( "requestId", Integer.toString( requestId ) );
                setPersistentProperty( "activateOnStartup",
                Boolean.TRUE.toString() );
                flush();
                this.persistentRequestId = requestId;
                transferJobId_ = dbAdapter.getTransferJobId( requestId );
                logger.debug(
                "setting transferid in statusTypes to : " +
                transferJobId_ );
                this.transferCount = dbAdapter.getTransferCount( requestId );
                this.numberPending = this.transferCount;
                this.numberActive=0;
                this.numberFailed=0;
                this.numberRestarted=0;
                this.numberCancelled=0;
            }
        } catch ( Exception e ) {
            throw new GridServiceException( e );
        }
    }
    
    
    /**
     *
     *@param  transferStatus  
     *@return  transferStatusType              
     */
    private TransferStatusType mapStatus( int transferStatus ) {
        try {
            
            if ( transferStatus == 0 ) {
                return TransferStatusType.Finished;
            }
            
            if ( transferStatus == 1 ) {
                return TransferStatusType.Retrying;
            }
            
            if ( transferStatus == 2 ) {
                return TransferStatusType.Failed;
            }
            
            if ( transferStatus == 3 ) {
                return TransferStatusType.Active;
            }
            
            if ( transferStatus == 4 ) {
                return TransferStatusType.Pending;
            }
            
            if ( transferStatus == 5 ) {
                return TransferStatusType.Cancelled;
            }
        }catch(Exception e) {
            logger.error("Exception while mapping status",e);
        }
        return null;
    }
    
    
    /**
     *
     *@param  credential  
     *@param  msgProt    
     */
    private void setNotifyProps( GSSCredential credential, Object msgProt ) {
        this.notifyProps = new HashMap();
        this.notifyProps.put( GSIConstants.GSI_MODE,
        GSIConstants.GSI_MODE_NO_DELEG );
        this.notifyProps.put( Constants.GSI_SEC_CONV, msgProt );
        this.notifyProps.put( Constants.AUTHORIZATION,
        SelfAuthorization.getInstance() );
        this.notifyProps.put( GSIConstants.GSI_CREDENTIALS, credential );
    }
    
    
    /**
     *@param  context                  
     *@exception  GridServiceException
     *@throws  Exception             
     */
    public void preDestroy( GridContext context )
    throws GridServiceException {
        super.preDestroy( context );
        logger.debug("Removing the delegated proxy from : " + this.proxyLocation);
        Util.destroy(this.proxyLocation);
        try {
            closeAll();
        } catch (Exception ioe) {
            logger.error("Error while closing connections",ioe);
        }
        logger.debug( "RFT instance destroyed" );
    }
    
    
    /**
     *  This method is called whenever a transfer status is changed!
     *
     *@param  transferJob            
     *@throws  GridServiceException 
     */
    public synchronized void statusChanged( TransferJob transferJob )
    throws GridServiceException {
        logger.debug( "Single File Transfer Status SDE changed "
        + "for:" + transferJob.getTransferId() 
        + "to " + transferJob.getStatus() );
        dbAdapter.update( transferJob );
        transferJobId_ = transferJob.getTransferId();
        this.setOverallStatusSDE(transferJob.getStatus());
        FileTransferJobStatusType statusType = new FileTransferJobStatusType();
        statusType.setTransferId( transferJob.getTransferId() );
        statusType.setDestinationUrl( transferJob.getDestinationUrl() );
        statusType.setStatus( mapStatus( transferJob.getStatus() ) );
        this.fileTransferStatusElement.setRequestStatus( statusType );
        this.singleFileTransferStatusSDE.setValue( fileTransferStatusElement );
        this.serviceData.add( singleFileTransferStatusSDE );
        singleFileTransferStatusSDE.notifyChange();
    }
    
    private void closeAll() {
        try {
            logger.debug("Closing all connections");
            for ( int i = 0; i < this.transferClients.size(); i++ ) {
                TransferClient transferClient = (TransferClient)
                this.transferClients.elementAt(i);
                transferClient.close();
            }
        } catch (Exception e){
            logger.debug("Exception while closing all connections",e);
        }
    }
    
    /**
     *  Gets the transferClient attribute of the RftImpl object
     *
     *@param  sourceURL                  
     *@param  destinationURL            
     *@exception  MalformedURLException  
     */
    public synchronized TransferClient 
        getTransferClient( String sourceURL, String destinationURL )
        throws MalformedURLException {
        TransferClient transferClient = null;
        boolean flag = false;
        for ( int i = 0; i < this.transferClients.size(); i++ ) {
            TransferClient tempTransferClient = (TransferClient) 
                this.transferClients.remove(i);
            GlobusURL source = tempTransferClient.getSourceURL();
            GlobusURL destination = tempTransferClient.getDestinationURL();
            int status = tempTransferClient.getStatus();
            logger.debug("status in recycled client: " + status);
            GlobusURL tempSource = new GlobusURL( sourceURL );
            GlobusURL tempDest = new GlobusURL( destinationURL );
            if ( (status != TransferJob.STATUS_ACTIVE)) { 
                flag = true;
            }
            if ( ( source.getHost().equals( tempSource.getHost() ) ) && 
                ( destination.getHost().equals( tempDest.getHost() ) ) && 
                flag ) {
                tempTransferClient.setStatus(TransferJob.STATUS_ACTIVE);
                transferClient = tempTransferClient;
                transferClient.setSourcePath( tempSource.getPath() );
                transferClient.setDestinationPath( tempDest.getPath() );
                logger.debug( "status: " + status );
                return transferClient;
            }
        }
        return transferClient;
    }
    
    
    /**
     * The transfer thread class 
     *
     *@author     madduri
     *@created    September 17, 2003
     */
    public class TransferThread
    extends Thread {
        
        TransferJob transferJob;
        TransferClient transferClient;
        int status;
        int attempts;
        BufferedReader stdInput;
        BufferedReader stdError;
        
        /**
         *  Constructor for the TransferThread object
         *
         *@param  transferJob  Description of the Parameter
         */
        TransferThread( TransferJob transferJob ) {
            this.transferJob = transferJob;
            this.attempts = transferJob.getAttempts();
            this.status = transferJob.getStatus();
        }
        
        
        /**
         *  Sets the transferClient attribute of the TransferThread object
         *
         *@param  transferClient  The new transferClient value
         */
        public void setTransferClient( TransferClient transferClient ) {
            this.transferClient = transferClient;
        }
        
        
        public void killThread()
        throws RftDBException {
            transferJob.setStatus( TransferJob.STATUS_CANCELLED );
            dbAdapter.update( transferJob );
        }
        
        
        public void run() {
            
            try {
                
                int tempId = transferJob.getTransferId();
                TransferThread transferThread;
                RFTOptionsType rftOptions = transferJob.getRftOptions();
                if (globalRFTOptionsType != null ) {
                    rftOptions = globalRFTOptionsType;
                }
                try {
                    transferClient = getTransferClient
                        ( transferJob.getSourceUrl(),
                    transferJob.getDestinationUrl() );
                    
                    if ( (transferClient == null )
                    || !connectionPoolingEnabled) {
                        logger.debug( "No transferClient reuse" 
                            + proxyLocation );
                        transferClient = new TransferClient( tempId,
                        transferJob.getSourceUrl(),
                        transferJob.getDestinationUrl(),
                        proxyLocation,
                        transferProgress,
                        serviceData,
                        transferProgressData,
                        restartMarkerServiceData,
                        restartMarkerDataType,
                        gridFTPRestartMarkerSD,
                        gridFTPRestartMarkerSDE,
                        gridFTPPerfMarkerSD,
                        gridFTPPerfMarkerSDE,
                        rftOptions );
                        transferJob.setStatus( TransferJob.STATUS_ACTIVE );
                        dbAdapter.update( transferJob );
                    } else {
//                        System.out.println( "Reusing TransferClient from the pool " + transferJob.getSourceUrl());
                        transferClient.setSourceURL( transferJob.getSourceUrl() );
                        transferClient.setDestinationURL
                            ( transferJob.getDestinationUrl() );
                        
                        MyMarkerListener myMarkerListener = new
                        MyMarkerListener( transferProgress, serviceData
                        , transferProgressData, transferClient.getSize()
                        , restartMarkerServiceData, restartMarkerDataType
                        , gridFTPRestartMarkerSD, gridFTPRestartMarkerSDE
                        , gridFTPPerfMarkerSD, gridFTPPerfMarkerSDE );
                        myMarkerListener.setTransferId(tempId);
                        transferClient.setMyMarkerListener( myMarkerListener );
                        transferClient.setStatus( TransferJob.STATUS_ACTIVE );
                    }
                } catch ( Exception e ) {
                    logger.error( "Error in Transfer Client" + e.toString(), e );
                    transferJob.setStatus( TransferJob.STATUS_FAILED );
                    statusChanged( transferJob );
                    
                    TransferJob newTransferJob = dbAdapter.getTransferJob(
                    requestId );
                    
                    if ( newTransferJob != null ) {
                        transferThread = new TransferThread( newTransferJob );
                        logger.debug(
                        "Attempts in new transfer: " +
                        newTransferJob.getAttempts() );
                        transferThread.start();
                        newTransferJob.setStatus( TransferJob.STATUS_ACTIVE );
                    } else {
                        logger.debug( "No more transfers " );
                        try {
                            closeAll();
                        } catch (Exception ioe) {
                            logger.error("Error closing connections",ioe);
                        } 
                    }
                    
                    throw new RemoteException( MessageUtils.toString( e ) );
                }
                
                String restartMarker = dbAdapter.getRestartMarker( tempId );
                boolean useExtended = false;
                
                if ( restartMarker != null ) {
                    transferClient.setRestartMarker( restartMarker );
                    useExtended = true;
                    
                }
                if ( transferClient != null ) {
                    if ( transferClient.getStatus() == 6 ) {
                        transferClient.setStatus( TransferJob.STATUS_EXPANDING );
                        transferJob.setStatus( TransferJob.STATUS_EXPANDING );
                    } else {
                        transferClient.setStatus( TransferJob.STATUS_ACTIVE );
                        transferClient.
                            setParallelStreams( rftOptions.getParallelStreams() );
                        transferClient.
                            setTcpBufferSize( rftOptions.getTcpBufferSize() );
                        transferClient.
                            setRFTOptions( rftOptions );
                        transferClient.transfer(useExtended);
                        transferJob.setStatus( TransferJob.STATUS_ACTIVE );
                        dbAdapter.update( transferJob );
                        transferJob.setStatus( transferClient.getStatus() );
                        
                        int x = transferClient.getStatus();
                        transferJob.
                            setAttempts( transferJob.getAttempts() + 1 );
                        
                        if ( x == 0 ) {
                            transferJob.
                                setStatus( TransferJob.STATUS_FINISHED );
                            this.status = TransferJob.STATUS_FINISHED;
                            statusChanged( transferJob );
                            transferProgress.setPercentComplete( 100 );
                            transferProgressData.setValue( transferProgress );
                            transferClient.
                                setStatus( TransferJob.STATUS_FINISHED );
                            transferClients.add( transferClient );
                            logger.debug("Adding transferclient to list");
                        } else if ( ( x == 1 ) &&
                        ( transferJob.getAttempts() < maxAttempts ) ) {
                            transferJob.
                                setStatus( TransferJob.STATUS_PENDING );
                            transferClient
                                .setStatus( TransferJob.STATUS_PENDING );
                            this.status = TransferJob.STATUS_PENDING;
                            logger.debug( "Transfer " 
                                + transferJob.getTransferId() + " Retrying" );
                            statusChanged( transferJob );
                            
                        } else if ( ( x == 2 ) ||
                        ( transferJob.getAttempts() >= maxAttempts ) ) {
                            transferJob.setStatus( TransferJob.STATUS_FAILED );
                            this.status = TransferJob.STATUS_FAILED;
                            logger.debug( "Transfer " 
                                + transferJob.getTransferId() + " Failed" );
                            statusChanged( transferJob );
                            transferClient
                                .setStatus( TransferJob.STATUS_FAILED );
                            //transferClients.add( transferClient );
                        } else {
                            transferJob
                                .setStatus( TransferJob.STATUS_RETRYING );
                            transferClient
                                .setStatus( TransferJob.STATUS_RETRYING );
                            this.status = TransferJob.STATUS_RETRYING;
                            statusChanged( transferJob );
                        }
                    }
                } else {
                    transferJob.setStatus( TransferJob.STATUS_FAILED );
                    this.status = TransferJob.STATUS_FAILED;
                    statusChanged( transferJob );
                    transferClient.setStatus( TransferJob.STATUS_FAILED );
                   // transferClients.add( transferClient );
                }
                
                dbAdapter.update( transferJob );
                synchronized( criticalSection ) {
                TransferJob newTransferJob = dbAdapter.getTransferJob(
                requestId );
                if ( newTransferJob != null ) {
                    logger.debug( "starting a new transfer " 
                    + newTransferJob.getTransferId() 
                        + "  " + newTransferJob.getStatus() );
                    logger.debug(numberActive + " " + concurrency);
                    transferThread = new TransferThread( newTransferJob );
                    newTransferJob.setStatus( TransferJob.STATUS_ACTIVE );
                    statusChanged( newTransferJob );
                    dbAdapter.update( newTransferJob );
                    transferThread.start();
                    
                } else {
                    URLExpander urlExpander = transferClient.getUrlExpander();
                    if ( urlExpander != null ) {
                        boolean expStatus = urlExpander.getStatus();
                        while ( expStatus == false ) {
                            try {
                                urlExpander.join();
                                expStatus = urlExpander.getStatus();
                            } catch ( InterruptedException ie ) {
                            }
                        }
                        TransferJob newTransferJob1 = 
                            dbAdapter.getTransferJob(requestId);
                        if ( newTransferJob1 == null ) {
                            logger.debug( "No more transfers " );
                            try {
                                closeAll();
                            } catch (Exception ioe) {
                                logger.error("Error closing connections",ioe);
                            } 
                        } else {
                            while (numberActive-1< concurrency) {
                                TransferJob tempTransferJob2 = 
                                dbAdapter.getTransferJob(requestId);
                                if ( tempTransferJob2 != null) {
                                    TransferThread transferThread2 = 
                                        new TransferThread( tempTransferJob2 );
                                    transferThread2.start();
                                    tempTransferJob2.
                                        setStatus( TransferJob.STATUS_ACTIVE );
                                    statusChanged( tempTransferJob2 );
                                } else {
                                    logger.debug("No more transfers");
                                }
                            }
                        }
                        
                    } else {
                        try {
                            logger.debug("no more transfers");
                            closeAll();
                        } catch (Exception e) {
                            logger.error(e);
                        }
                    }
                }
                }
            } catch ( Exception ioe ) {
                logger.error( "Error in Transfer Thread" 
                    + ioe.toString(), ioe );
            } catch ( Throwable ee ) {
                logger.error( "Error in Transfer Thread" + ee.toString(), ee );
            }
        }
    }
}

