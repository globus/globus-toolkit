/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
package org.globus.ogsa.impl.base.multirft.util;
import java.io.File;
import java.rmi.RemoteException;
import java.util.Vector;

import java.util.Vector;

import org.apache.log4j.Logger;

import org.globus.ftp.GridFTPClient;
import org.globus.ftp.GridFTPSession;
import org.globus.ftp.HostPort;
import org.globus.ftp.MlsxEntry;
import org.globus.ogsa.base.multirft.TransferType;
import org.globus.ogsa.base.multirft.RFTOptionsType;
import org.globus.ogsa.impl.base.multirft.TransferDbAdapter;
import org.globus.ogsa.impl.base.multirft.TransferJob;
import org.globus.ogsa.impl.base.multirft.RftDBException;
import org.globus.ogsa.utils.MessageUtils;

import org.globus.util.GlobusURL;

/**
 *  Description This class should take the sourceUrl and destination Url from
 *  RftImpl of the Class and return a Vector of corresponding Fully Qualified
 *  gsiftp urls
 *
 *@author     madduri
 *@created    September 28, 2003
 */
public class URLExpander extends Thread {

    TransferJob transferJob;
    GridFTPClient sourceHost, destinationHost;
    String sourcePath, destinationPath;
    FileSystemUtil fileSystemUtil;
    Vector processURLs;
    Vector sourceUrlsEx;
	Vector transferJobVector;
    GlobusURL sourceGlobusUrl, destinationGlobusUrl;
    TransferDbAdapter dbAdapter;
    boolean done = false;
    RFTOptionsType rftOptions = null;
    // This transferJob should include directory in source and dest
    private static Logger logger = Logger.getLogger( URLExpander.class.getName() );


    /**
     *  Constructor for the URLExpander object
     *
     *@param  sourceHost            source gridftp server
     *@param  destinationHost       Description of the Parameter
     *@param  sourceGlobusUrl       Description of the Parameter
     *@param  destinationGlobusUrl  Description of the Parameter
     *@exception  RemoteException
     */
    public URLExpander( GridFTPClient sourceHost, GridFTPClient destinationHost,
            GlobusURL sourceGlobusUrl, GlobusURL destinationGlobusUrl
            ,RFTOptionsType rftOptions )
             throws RemoteException {
        try {
            this.sourceHost = sourceHost;
            this.destinationHost = destinationHost;
            this.sourceGlobusUrl = sourceGlobusUrl;
            this.destinationGlobusUrl = destinationGlobusUrl;
            this.sourcePath = "/" + sourceGlobusUrl.getPath();
            this.destinationPath = "/" + destinationGlobusUrl.getPath();
            this.fileSystemUtil = new FileSystemUtil();
            this.rftOptions = rftOptions;
            processURLs = new Vector();
            this.sourceUrlsEx = new Vector();
            this.sourceUrlsEx.add( this.sourcePath );
            this.fileSystemUtil.setGridFTPClient( this.destinationHost );
            this.dbAdapter = TransferDbAdapter.getTransferDbAdapter();
            this.fileSystemUtil.changeDir( destinationPath );
			transferJobVector = new Vector();
        } catch ( Exception e ) {
            logger.debug( "Invalid source/dest urls" );
            throw new RemoteException( MessageUtils.toString( e ) );
        }
    }


    /**
     *  Description of the Method
     *
     *@param  localSourcePath  Description of the Parameter
     *@return                  Description of the Return Value
     *@exception  Exception    Description of the Exception
     */
    public Vector doMlsd( String localSourcePath ) {
        try {
            //this.sourceHost.setType(GridFTPSession.TYPE_ASCII);
            logger.debug( "Source Path : " + localSourcePath );
            HostPort hp = this.sourceHost.setLocalPassive();
            this.sourceHost.setActive( hp );
            this.sourceHost.changeDir( localSourcePath );
            return this.sourceHost.mlsd();
        } catch (Exception e) {
            logger.debug("Exception in mlsd " + e.getMessage(),e);
        }
        return null;
    }


    /**
     *  Gets the status attribute of the URLExpander object
     *
     *@return    The status value
     */
    public boolean getStatus() {
        return this.done;
    }


    /**
     *  this invokes the MLST command from GridFTPClient on the source hands it
     *  over to parser utility which gives set of directories that need to be
     *  made at the destination.Recursive directory traversal or Iterative?
     */
    public void run() {
        try {
            while ( this.sourceUrlsEx.size() > 0 ) {
                logger.debug(
                        "Size of SourceUrlsEx " + this.sourceUrlsEx.size() );
                String currentUrl = (String) this.sourceUrlsEx.remove( 0 );
                logger.debug( "Current dir : " + currentUrl );
                Vector v = doMlsd( currentUrl );

                while ( !v.isEmpty() ) {
                    MlsxEntry f = (MlsxEntry) v.remove( 0 );
                    if ( f.get( f.TYPE ).equals( f.TYPE_DIR ) ) {
                        logger.debug( "The directory name: " + f.getFileName() );
                        fileSystemUtil.makeDirectory( f.getFileName() );
                        String newSourcePath = currentUrl + "/" + f.getFileName();
                        logger.debug
                                ( "This dir is added to list for further processing " );
                        logger.debug( newSourcePath );
                        this.sourceUrlsEx.add( newSourcePath );
                    } else if ( f.get( f.TYPE ).equals( f.TYPE_FILE ) ) {
                        logger.debug( "This is a file : " + f.getFileName() );
                        String newSourceUrl = "gsiftp://"
                                 + this.sourceGlobusUrl.getHost()
                                 + ":"
                                 + this.sourceGlobusUrl.getPort()
                                 + currentUrl + File.separator
                                 + f.getFileName();
                        int temp = currentUrl.lastIndexOf( "//" );
                        String mkdir = "";
                        if ( temp != -1 ) {
                            mkdir = currentUrl.substring
                                    ( currentUrl.lastIndexOf( "//" ) + 2 );
                        }
                        String newDestinationUrl = "gsiftp://"
                                 + this.destinationGlobusUrl.getHost()
                                 + ":"
                                 + this.destinationGlobusUrl.getPort()
                                 + this.destinationPath
                                 + File.separator + mkdir
                                 + File.separator + f.getFileName();
                        logger.debug( "Adding these to db : "
                                 + newSourceUrl + "  " + newDestinationUrl );
                        TransferType transferType = new TransferType();
                        transferType.setSourceUrl( newSourceUrl );
                        transferType.setDestinationUrl( newDestinationUrl );
                        TransferJob transferJob = new
                                TransferJob( transferType, 0, 4 );
                        transferJob.setRftOptions(this.rftOptions);
				//		this.transferJobVector.add( transferJob );
                        this.dbAdapter.storeTransferJob( transferJob );
                    }
                }
                currentUrl = (String) this.sourceUrlsEx.elementAt( 0 );
                String mkdir = currentUrl.substring
                        ( currentUrl.lastIndexOf( "//" ) + 2 );
                logger.debug( "mkdir: " + mkdir );

                mkdir = mkdir.trim();
                if ( !mkdir.equals( "" ) ) {
                    mkdir = this.destinationPath + mkdir;
                    this.fileSystemUtil.changeDir( mkdir );
                }
            }
        } catch ( Exception e ) {
            logger.error( e.getMessage() );
        }
        if ( this.sourceUrlsEx.size() == 0 ) {
            System.out.println( "UrlExpander is done" );
            this.done = true;
        }
    }
}


