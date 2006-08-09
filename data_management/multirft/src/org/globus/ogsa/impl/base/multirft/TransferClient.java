/*
 *  This file is licensed under the terms of the Globus Toolkit Public
 *  License, found at http://www.globus.org/toolkit/download/license.html.
 */
package org.globus.ogsa.impl.base.multirft;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.net.MalformedURLException;
import java.net.URL;

import java.rmi.RemoteException;

import org.apache.log4j.Logger;

import org.globus.ftp.ByteRangeList;
import org.globus.ftp.DataChannelAuthentication;
import org.globus.ftp.DataSink;
import org.globus.ftp.DataSinkStream;
import org.globus.ftp.DataSource;
import org.globus.ftp.DataSourceStream;
import org.globus.ftp.FileRandomIO;
import org.globus.ftp.GridFTPClient;
import org.globus.ftp.GridFTPRestartMarker;
import org.globus.ftp.GridFTPSession;
import org.globus.ftp.RetrieveOptions;
import org.globus.ftp.exception.FTPException;
import org.globus.ftp.exception.ServerException;
import org.globus.ftp.vanilla.FTPServerFacade;

import org.globus.util.Util;

import org.globus.gsi.gssapi.auth.IdentityAuthorization;

import org.globus.ogsa.ServiceData;
import org.globus.ogsa.ServiceDataSet;
import org.globus.ogsa.base.multirft.FileTransferProgressType;
import org.globus.ogsa.base.multirft.FileTransferRestartMarker;
import org.globus.ogsa.base.multirft.GridFTPPerfMarkerElement;
import org.globus.ogsa.base.multirft.GridFTPRestartMarkerElement;
import org.globus.ogsa.base.multirft.RFTOptionsType;
import org.globus.ogsa.impl.base.multirft.MyMarkerListener;
import org.globus.ogsa.impl.base.multirft.TransferDbOptions;
import org.globus.ogsa.impl.base.multirft.TransferJob;
import org.globus.ogsa.impl.base.multirft.util.FileSystemUtil;
import org.globus.ogsa.impl.base.multirft.util.URLExpander;
import org.globus.ogsa.utils.MessageUtils;

import org.globus.util.GlobusURL;

import org.gridforum.jgss.ExtendedGSSCredential;
import org.gridforum.jgss.ExtendedGSSManager;

import org.gridforum.ogsi.ServiceDataType;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;


/**
 *  Description of the Class
 *
 *@author     madduri
 *@created    October 17, 2003
 */
public class TransferClient {

    GridFTPClient sourceHost;
    GridFTPClient destinationHost;
    String sourcePath;
    String destinationPath;
    String proxyPath;
    String sourceHostName;
    String destinationHostName;
    int status = -1;
    int transferid;
    int parallelism;
    int tcpBufferSize;
    int sourcePort;
    int destinationPort;
    GSSCredential credential;
    MyMarkerListener markerListener;
    GlobusURL sourceGlobusURL;
    GlobusURL destinationGlobusURL;
    long size;
    RFTOptionsType rftOptions;
    String sourceSubjectName;
    String destinationSubjectName;
    String subjectName;
    TransferDbOptions dbOptions;
    FileSystemUtil fileSystemUtil;
    static int counter = 0;
    URLExpander urlExpander = null;
    private static Logger logger = Logger.getLogger( TransferClient.class.getName() );


    /**
     *  Constructor for the TransferClient object
     */
    public TransferClient() { }


    /**
     *  Sets the sourceURL attribute of the TransferClient object
     *
     *@param  sourceURL            The new sourceURL value
     *@exception  RemoteException  Description of the Exception
     */
    public void setSourceURL( String sourceURL )
             throws RemoteException {
        try {
            this.sourceGlobusURL = new GlobusURL( sourceURL );
        } catch ( Exception e ) {
            setStatus( TransferJob.STATUS_FAILED );
            logger.debug( "Invalid Source URL" );
            throw new RemoteException( MessageUtils.toString( e ) );
        }
    }


    /**
     *  Sets the destinationURL attribute of the TransferClient object
     *
     *@param  destinationURL       The new destinationURL value
     *@exception  RemoteException  Description of the Exception
     */
    public void setDestinationURL( String destinationURL )
             throws RemoteException {
        try {
            this.destinationGlobusURL = new GlobusURL( destinationURL );
        } catch ( Exception e ) {
            setStatus( TransferJob.STATUS_FAILED );
            logger.debug( "Invalid Destination URL" );
            throw new RemoteException( MessageUtils.toString( e ) );
        }
    }


    /**
     *  Gets the sourceURL attribute of the TransferClient object
     *
     *@return    The sourceURL value
     */
    public GlobusURL getSourceURL() {
        return this.sourceGlobusURL;
    }


    /**
     *  Gets the destinationURL attribute of the TransferClient object
     *
     *@return    The destinationURL value
     */
    public GlobusURL getDestinationURL() {
        return this.destinationGlobusURL;
    }


    /**
     *  Sets the sourceHost attribute of the TransferClient object
     *
     *@param  sourceURL            The new sourceHost value
     *@exception  RemoteException  Description of the Exception
     */
    public void setSourceHost( String sourceURL )
             throws RemoteException {
        try {
            this.sourceGlobusURL = new GlobusURL( sourceURL );
            this.sourceHost = new GridFTPClient( this.sourceGlobusURL.getHost(),
                    this.sourceGlobusURL.getPort() );
        } catch ( Exception e ) {
            setStatus( TransferJob.STATUS_FAILED );
            logger.debug( "Unable to create GridFTP Client to : " + this.sourceGlobusURL.getHost() );
            throw new RemoteException( MessageUtils.toString( e ) );
        }
    }


    /**
     *  Sets the destinationHost attribute of the TransferClient object
     *
     *@param  destURL              The new destinationHost value
     *@exception  RemoteException  Description of the Exception
     */
    public void setDestinationHost( String destURL )
             throws RemoteException {
        try {
            this.destinationGlobusURL = new GlobusURL( destURL );
            this.destinationHost = new GridFTPClient( this.destinationGlobusURL.getHost(),
                    this.destinationGlobusURL.getPort() );
        } catch ( Exception e ) {
            setStatus( TransferJob.STATUS_FAILED );
            logger.debug( "Unable to create GridFTP Client to : " + this.destinationGlobusURL.getHost() );
            throw new RemoteException( MessageUtils.toString( e ) );
        }
    }


    /**
     *  Sets the status attribute of the TransferClient object
     *
     *@param  status  The new status value
     */
    public synchronized void setStatus( int status ) {
        this.status = status;
    }


    /**
     *  Sets the credential attribute of the TransferClient object
     *
     *@param  proxyPath                       The new credential value
     *@exception  org.ietf.jgss.GSSException  Description of the Exception
     */
    public void setCredential( String proxyPath )
             throws org.ietf.jgss.GSSException {
        this.credential = loadCredential( proxyPath );
    }


    /**
     *  Description of the Method
     *
     *@exception  RemoteException  Description of the Exception
     */
    public void initialize()
             throws RemoteException {
        try {
            setTransferParams( this.destinationHost, this.credential );
            setTransferParams( this.sourceHost, this.credential );
            this.size = this.sourceHost.getSize( this.sourcePath );
        } catch ( Exception e ) {
            throw new RemoteException( MessageUtils.toString( e ) );
        }
    }


    /**
     *  Sets the transferId attribute of the TransferClient object
     *
     *@param  transferId  The new transferId value
     */
    public void setTransferId( int transferId ) {
        this.transferid = transferId;
    }


    /**
     *  Sets the rftOptions attribute of the TransferClient object
     *
     *@param  rftOptions  The new rftOptions value
     */
    public void setRftOptions( RFTOptionsType rftOptions ) {
        this.rftOptions = rftOptions;
    }


    /**
     *  Sets the dbOptions attribute of the TransferClient object
     *
     *@param  dbOptions  The new dbOptions value
     */
    public void setDbOptions( TransferDbOptions dbOptions ) {
        this.dbOptions = dbOptions;
    }


    /**
     *  Sets the myMarkerListener attribute of the TransferClient object
     *
     *@param  transferProgress             The new myMarkerListener value
     *@param  serviceData                  The new myMarkerListener value
     *@param  transferProgressData         The new myMarkerListener value
     *@param  restartMarkerServiceData     The new myMarkerListener value
     *@param  restartMarker                The new myMarkerListener value
     *@param  gridFTPRestartMarkerSD       The new myMarkerListener value
     *@param  gridFTPRestartMarkerElement  The new myMarkerListener value
     *@param  gridFTPPerfMarkerSD          The new myMarkerListener value
     *@param  gridFTPPerfMarkerElement     The new myMarkerListener value
     */
    public void setMyMarkerListener( FileTransferProgressType transferProgress,
            ServiceDataSet serviceData,
            ServiceData transferProgressData,
            ServiceData restartMarkerServiceData,
            FileTransferRestartMarker restartMarker,
            ServiceData gridFTPRestartMarkerSD,
            GridFTPRestartMarkerElement gridFTPRestartMarkerElement,
            ServiceData gridFTPPerfMarkerSD,
            GridFTPPerfMarkerElement gridFTPPerfMarkerElement ) {
        this.markerListener = new MyMarkerListener( transferProgress,
                serviceData, transferProgressData, this.size,
                restartMarkerServiceData, restartMarker,
                gridFTPRestartMarkerSD, gridFTPRestartMarkerElement,
                gridFTPPerfMarkerSD, gridFTPPerfMarkerElement );
        this.markerListener.setTransferId( this.transferid );
    }


    /**
     *  Sets the myMarkerListener attribute of the TransferClient object
     *
     *@param  markerListener  The new myMarkerListener value
     */
    public void setMyMarkerListener( MyMarkerListener markerListener ) {
        this.markerListener = markerListener;
    }


    /**
     *  Gets the size attribute of the TransferClient object
     *
     *@return    The size value
     */
    public long getSize() {
        return this.size;
    }


    /**
     *  Gets the urlExpander attribute of the TransferClient object
     *
     *@return    The urlExpander value
     */
    public URLExpander getUrlExpander() {
        return this.urlExpander;
    }


    /**
     *  Sets the authorization attribute of the TransferClient object
     */
    public void setAuthorization() {
        subjectName = this.rftOptions.getSubjectName();
        sourceSubjectName = this.rftOptions.getSourceSubjectName();
        destinationSubjectName = this.rftOptions.getDestinationSubjectName();

        if ( subjectName != null ) {
            destinationHost.setAuthorization( new IdentityAuthorization(
                    subjectName ) );
            sourceHost.setAuthorization( new IdentityAuthorization(
                    subjectName ) );
        }
        if ( sourceSubjectName != null ) {
            sourceHost.setAuthorization( new IdentityAuthorization(
                    sourceSubjectName ) );
        }

        if ( destinationSubjectName != null ) {
            destinationHost.setAuthorization( new IdentityAuthorization(
                    destinationSubjectName ) );
        }
    }


    /**
     *  Constructor for the TransferClient object
     *
     *@param  transferid                   Description of the Parameter
     *@param  sourceURL                    Description of the Parameter
     *@param  destinationURL               Description of the Parameter
     *@param  proxyPath                    Description of the Parameter
     *@param  transferProgress             Description of the Parameter
     *@param  serviceData                  Description of the Parameter
     *@param  transferProgressData         Description of the Parameter
     *@param  restartMarkerServiceData     Description of the Parameter
     *@param  restartMarker                Description of the Parameter
     *@param  gridFTPRestartMarkerSD       Description of the Parameter
     *@param  gridFTPRestartMarkerElement  Description of the Parameter
     *@param  gridFTPPerfMarkerSD          Description of the Parameter
     *@param  gridFTPPerfMarkerElement     Description of the Parameter
     *@param  rftOptions                   Description of the Parameter
     *@exception  RemoteException          Description of the Exception
     */
    public TransferClient( int transferid, String sourceURL,
            String destinationURL, String proxyPath,
            FileTransferProgressType transferProgress,
            ServiceDataSet serviceData,
            ServiceData transferProgressData,
            ServiceData restartMarkerServiceData,
            FileTransferRestartMarker restartMarker,
            ServiceData gridFTPRestartMarkerSD,
            GridFTPRestartMarkerElement gridFTPRestartMarkerElement,
            ServiceData gridFTPPerfMarkerSD,
            GridFTPPerfMarkerElement gridFTPPerfMarkerElement,
            RFTOptionsType rftOptions )
             throws RemoteException {

        try {
            this.transferid = transferid;
            logger.debug( "transfer id in transfer client: " + this.transferid );
            sourceGlobusURL = new GlobusURL( sourceURL );
            if ( !( sourceGlobusURL.getProtocol() ).equals( "gsiftp" ) ) {
                throw new RemoteException( "Invalid protocol used" );
            }
            destinationGlobusURL = new GlobusURL( destinationURL );
            if ( !( destinationGlobusURL.getProtocol() ).equals( "gsiftp" ) ) {
                throw new RemoteException( "Invalid protocol used" );
            }
            sourceHostName = sourceGlobusURL.getHost();
            destinationHostName = destinationGlobusURL.getHost();
            sourcePath = "/" + sourceGlobusURL.getPath();
            destinationPath = "/" + destinationGlobusURL.getPath();
            sourcePort = sourceGlobusURL.getPort();
            destinationPort = destinationGlobusURL.getPort();
            sourceHost = new GridFTPClient( sourceGlobusURL.getHost(),
                    sourceGlobusURL.getPort() );
            destinationHost = new GridFTPClient( destinationGlobusURL.getHost(),
                    destinationGlobusURL.getPort() );
            this.fileSystemUtil = new FileSystemUtil();
            this.fileSystemUtil.setGridFTPClient( destinationHost );
            this.credential = loadCredential( proxyPath );
            this.rftOptions = rftOptions;
            if ( this.rftOptions != null ) {
                subjectName = this.rftOptions.getSubjectName();
                sourceSubjectName = this.rftOptions.getSourceSubjectName();
                logger.debug("source sub name "  + sourceSubjectName );
                destinationSubjectName = this.rftOptions.getDestinationSubjectName();
                logger.debug("dest sub name "  + destinationSubjectName);
            }

            if ( subjectName != null ) {
                destinationHost.setAuthorization( new IdentityAuthorization(
                        subjectName ) );
                logger.debug("subjectName : " + subjectName);
                sourceHost.setAuthorization( new IdentityAuthorization(
                        subjectName ) );
            }

            if ( sourceSubjectName != null ) {
                logger.debug("source sub name "  + sourceSubjectName );
                sourceHost.setAuthorization( new IdentityAuthorization(
                        sourceSubjectName ) );
            }

            if ( destinationSubjectName != null ) {
                logger.debug("setting dest sub name :  " + destinationSubjectName);
                destinationHost.setAuthorization( new IdentityAuthorization(
                        destinationSubjectName ) );
            } else {
                logger.debug("dest sub is null");
            }


            try {
                setTransferParams( destinationHost, this.credential );
            } catch ( Exception ae1 ) {
                throw new RemoteException( MessageUtils.toString( ae1 ) );
            }
            try {
                setTransferParams( sourceHost, this.credential );
            } catch ( Exception ae2 ) {
                throw new RemoteException( MessageUtils.toString( ae2 ) );
            }
            counter++;
            logger.debug( "This is transfer # " + counter );
            if ( this.sourcePath.endsWith( "/" ) ) {
                logger.debug( "Source url contains a directory" );
                logger.debug( "More processing needs to be done" );
                this.setStatus( TransferJob.STATUS_EXPANDING );
                this.urlExpander = new URLExpander
                        ( this.sourceHost, this.destinationHost, sourceGlobusURL
                        , destinationGlobusURL,this.rftOptions );
                this.urlExpander.start();
            } else if ( this.status != TransferJob.STATUS_FAILED ) {
                size = sourceHost.getSize( sourcePath );
                this.markerListener = new MyMarkerListener( transferProgress,
                        serviceData,
                        transferProgressData, size,
                        restartMarkerServiceData,
                        restartMarker,
                        gridFTPRestartMarkerSD,
                        gridFTPRestartMarkerElement,
                        gridFTPPerfMarkerSD,
                        gridFTPPerfMarkerElement );
                this.markerListener.setTransferId( transferid );
                logger.debug( "Transfer Id in TransferClient : " + transferid );
            }
        } catch ( MalformedURLException mue ) {
            setStatus( TransferJob.STATUS_FAILED );
            logger.error( "Error in TransferClient:Invalid URLs", mue );
        } catch ( Exception e ) {
            logger.error( "Error in TransferClient", e );
        }

    }


    /**
     *  DOCUMENT ME!
     *
     *@param  credPath       DOCUMENT ME!
     *@return                DOCUMENT ME!
     *@throws  GSSException  DOCUMENT ME!
     */
    public static GSSCredential loadCredential( String credPath )
             throws GSSException {

        ExtendedGSSManager manager = (ExtendedGSSManager) ExtendedGSSManager.getInstance();
        String handle = "X509_USER_PROXY=" + credPath;

        return manager.createCredential( handle.getBytes(),
                ExtendedGSSCredential.IMPEXP_MECH_SPECIFIC,
                GSSCredential.DEFAULT_LIFETIME, null,
                GSSCredential.INITIATE_AND_ACCEPT );
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  credential     DOCUMENT ME!
     *@return                DOCUMENT ME!
     *@throws  GSSException  DOCUMENT ME!
     */
    public static String saveCredential( GSSCredential credential )
             throws GSSException {

        if ( !( credential instanceof ExtendedGSSCredential ) ) {
            throw new GSSException( GSSException.FAILURE );
        }

        ExtendedGSSManager manager = (ExtendedGSSManager) ExtendedGSSManager.getInstance();
        byte[] buf = ( (ExtendedGSSCredential) credential ).export(
                ExtendedGSSCredential.IMPEXP_MECH_SPECIFIC );

        if ( buf == null ) {
            throw new GSSException( GSSException.FAILURE );
        }

        String handle = new String( buf );
        int pos = handle.indexOf( '=' );

        if ( pos == -1 ) {
            throw new GSSException( GSSException.FAILURE );
        }

        return handle.substring( pos + 1 ).trim();
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  proxyPath  DOCUMENT ME!
     */
    public void setProxyPath( String proxyPath ) {
        this.proxyPath = proxyPath;
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  host  DOCUMENT ME!
     */
    public void setSource( GridFTPClient host ) {
        this.sourceHost = host;
    }


    /**
     *  DOCUMENT ME!
     *
     *@return    DOCUMENT ME!
     */
    public GridFTPClient getSource() {

        return this.sourceHost;
    }


    /**
     *  DOCUMENT ME!
     *
     *@return    DOCUMENT ME!
     */
    public synchronized int getStatus() {

        return this.status;
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  destinationHost  DOCUMENT ME!
     */
    public void setDestination( GridFTPClient destinationHost ) {
        this.destinationHost = destinationHost;
    }


    /**
     *  DOCUMENT ME!
     *
     *@return    DOCUMENT ME!
     */
    public GridFTPClient getDestination() {

        return this.destinationHost;
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  destPath  DOCUMENT ME!
     */
    public void setDestinationPath( String destPath ) {
        this.destinationPath = "/" + destPath;
    }


    /**
     *  DOCUMENT ME!
     *
     *@return    DOCUMENT ME!
     */
    public int getTransferID() {

        return this.transferid;
    }


    /**
     *  DOCUMENT ME!
     *
     *@return    DOCUMENT ME!
     */
    public String getDestinationPath() {

        return destinationPath;
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  sourcePath  DOCUMENT ME!
     */
    public synchronized void setSourcePath( String sourcePath ) {
        this.sourcePath = "/" + sourcePath;
        this.markerListener = null;
        try {
            this.size = sourceHost.getSize( this.sourcePath );
        } catch ( Exception e ) {
            logger.error( "Unable to get size of : " + sourcePath, e );
            setStatus( TransferJob.STATUS_FAILED );
        }

    }


    /**
     *  DOCUMENT ME!
     *
     *@return    DOCUMENT ME!
     */
    public String getSourcePath() {

        return this.sourcePath;
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  rftOptions  DOCUMENT ME!
     */
    public void setRFTOptions( RFTOptionsType rftOptions ) {
        this.rftOptions = rftOptions;
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  host           DOCUMENT ME!
     *@param  cred           DOCUMENT ME!
     *@exception  Exception  Description of the Exception
     */
    public void setTransferParams( GridFTPClient host, GSSCredential cred )
             throws Exception {

        try {
            host.authenticate( cred );

            if ( rftOptions.isBinary() ) {
                host.setType( GridFTPSession.TYPE_IMAGE );
            } else {
                host.setType( GridFTPSession.TYPE_ASCII );
            }

            host.setMode( GridFTPSession.MODE_EBLOCK );

            if ( rftOptions.isDcau() ) {
                host.setDataChannelAuthentication(
                        DataChannelAuthentication.SELF );
                host.setProtectionBufferSize( 16384 );
            } else {
                host.setDataChannelAuthentication(
                        DataChannelAuthentication.NONE );
            }
        } catch ( Exception e ) {
            logger.debug( "Error in setting Params", e );
            setStatus( TransferJob.STATUS_FAILED );

        }
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  marker  DOCUMENT ME!
     */
    public void setRestartMarker( String marker ) {

        try {
            marker = "Range Marker " + marker;

            GridFTPRestartMarker restartmarker = new GridFTPRestartMarker(
                    marker );
            ByteRangeList list = new ByteRangeList();
            list.merge( restartmarker.toVector() );
            this.sourceHost.setRestartMarker( list );
        } catch ( Exception e ) {
            logger.error( "Error in setting the restart marker", e );
        }
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  parallel  DOCUMENT ME!
     */
    public void setParallelStreams( int parallel ) {
        this.parallelism = parallel;
    }

    public void close() {
        try {
            this.sourceHost.close();
            this.destinationHost.close();
        } catch (Exception e) {
            logger.debug("Exception while closing client connection",e); 
        }
    }

    /**
     *  DOCUMENT ME!
     *
     *@param  tcpBufferSize  DOCUMENT ME!
     */
    public void setTcpBufferSize( int tcpBufferSize ) {
        this.tcpBufferSize = tcpBufferSize;
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  useExtended  Description of the Parameter
     */
    public void transfer( boolean useExtended ) {
        if ( useExtended ) {
            if ( rftOptions.isNotpt() ) {
                noTptTransfer();
            } else {
                tptTransfer();
            }
        } else {
            if ( rftOptions.isNotpt() ) {
                noTptNonExtendedTransfer();
            } else {
                tptNonExtendedTransfer();
            }
        }
    }

    private boolean checkSize() 
    throws IOException,ServerException {
        long destSize = this.destinationHost.getSize(this.destinationPath);
        if ( this.size == destSize ) {
            return true;
        } else { 
            return false;
        }
    }
    
    /**
     *  Description of the Method
     */
    private void tptNonExtendedTransfer() {

        try {
            logger.debug( "In NonExtended transfer" + this.transferid );
            sourceHost.setOptions( new RetrieveOptions( parallelism ) );
            sourceHost.setTCPBufferSize( this.tcpBufferSize );
            destinationHost.setTCPBufferSize( this.tcpBufferSize );
            sourceHost.transfer( this.sourcePath,
                    this.destinationHost, this.destinationPath, false, this.markerListener );
            logger.debug( "Transfer done " + this.transferid );
            this.markerListener = null;
            setStatus( TransferJob.STATUS_FINISHED );
        } catch ( Exception e ) {
            logger.debug( "Exception in transfer", e );

            if ( status != TransferJob.STATUS_FAILED ) {
                setStatus( TransferJob.STATUS_RETRYING );
            }
        }
    }


    /**
     *  Description of the Method
     */
    private void noTptNonExtendedTransfer() {

        try {
            File fullLocalFile = File.createTempFile("TempRFT",
                    String.valueOf(transferid));
            Util.setOwnerAccessOnly(fullLocalFile.getAbsolutePath());
            sourceHost.setOptions( new RetrieveOptions( parallelism ) );
            sourceHost.setTCPBufferSize( this.tcpBufferSize );

            DataSink sink = null;
            sink = new FileRandomIO( new java.io.RandomAccessFile( fullLocalFile,
                    "rw" ) );
            sourceHost.get( sourcePath, sink, this.markerListener );
            sourceHost.close();
            destinationHost.setOptions( new RetrieveOptions( parallelism ) );
            destinationHost.setTCPBufferSize( this.tcpBufferSize );

            DataSource source = null;
            source = new FileRandomIO( new java.io.RandomAccessFile(
                    fullLocalFile, "r" ) );
            destinationHost.put( destinationPath, source,
                    this.markerListener );
            destinationHost.close();
            setStatus( TransferJob.STATUS_FINISHED );
        } catch ( FTPException e ) {
            logger.debug( "Exception in noTpt", e );

            if ( status != TransferJob.STATUS_FAILED ) {
                setStatus( TransferJob.STATUS_RETRYING );
            }
        } catch ( IOException ioe ) {
            logger.debug( "IOException in noTpt", ioe );
        }
    }


    /**
     *  DOCUMENT ME!
     */
    private void tptTransfer() {

        try {
            logger.debug( "In Transfer Client" );
            sourceHost.setOptions( new RetrieveOptions( parallelism ) );
            sourceHost.setTCPBufferSize( this.tcpBufferSize );
            destinationHost.setTCPBufferSize( this.tcpBufferSize );
            sourceHost.extendedTransfer( this.sourcePath, this.destinationHost,
                    this.destinationPath, this.markerListener );
            logger.debug( "Transfer done" );
            this.markerListener = null;
            setStatus( TransferJob.STATUS_FINISHED );
        } catch ( Exception e ) {
            logger.debug( "Exception in transfer", e );

            if ( status != TransferJob.STATUS_FAILED ) {
                setStatus( TransferJob.STATUS_RETRYING );
            }
        }
    }


    /**
     *  DOCUMENT ME!
     */
    private void noTptTransfer() {

        try {
            File fullLocalFile = File.createTempFile("TempRFT",
                    String.valueOf(transferid));
            Util.setOwnerAccessOnly(fullLocalFile.getAbsolutePath());

            sourceHost.setOptions( new RetrieveOptions( parallelism ) );
            sourceHost.setTCPBufferSize( this.tcpBufferSize );

            DataSink sink = null;
            sink = new FileRandomIO( new java.io.RandomAccessFile( fullLocalFile,
                    "rw" ) );
            sourceHost.extendedGet( sourcePath, size, sink, this.markerListener );
            sourceHost.close();
            destinationHost.setOptions( new RetrieveOptions( parallelism ) );
            destinationHost.setTCPBufferSize( this.tcpBufferSize );

            DataSource source = null;
            source = new FileRandomIO( new java.io.RandomAccessFile(
                    fullLocalFile, "r" ) );
            destinationHost.extendedPut( destinationPath, source,
                    this.markerListener );
            destinationHost.close();
            setStatus( TransferJob.STATUS_FINISHED );
        } catch ( FTPException e ) {
            logger.debug( "Exception in noTpt", e );

            if ( status != TransferJob.STATUS_FAILED ) {
                setStatus( TransferJob.STATUS_RETRYING );
            }
        } catch ( IOException ioe ) {
            logger.debug( "IOException in noTpt", ioe );
        }
    }
}

