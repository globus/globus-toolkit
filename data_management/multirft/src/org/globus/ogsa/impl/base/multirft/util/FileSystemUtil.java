/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
package org.globus.ogsa.impl.base.multirft.util;

import org.globus.ftp.GridFTPClient;

import java.util.StringTokenizer;
import java.util.Vector;
import java.io.IOException;
import java.rmi.RemoteException;
import org.globus.ftp.exception.ServerException;
import org.globus.ftp.exception.ClientException;
import org.globus.ftp.exception.UnexpectedReplyCodeException;

import org.apache.log4j.Logger;
public class FileSystemUtil {

    GridFTPClient gridFTPClient = null;
    
    private static Logger logger = Logger.getLogger( FileSystemUtil.class.getName() );
    public void setGridFTPClient(GridFTPClient gridFTPClient) {
        this.gridFTPClient = gridFTPClient;
    }
    
    /* this method takes a string which has a set of directories
    *   that are delimited by / 
    */
    public void makeDirectory(String dir)
    throws IOException,ServerException {
        try {
                logger.debug("dir: " + dir);
                this.gridFTPClient.makeDir(dir);
            
        } catch(ServerException e) {
            //throw new RemoteException("Exception while making directories"+e.getMessage());
        }       
    }
    /* this method takes a string and cd's to that location
    */
    public void changeDir(String dirString)
    throws IOException,ServerException {
        try {
            this.gridFTPClient.changeDir(dirString);
        }catch(Exception e) {
           logger.debug("creating dir: " + dirString);
           this.makeDirectory(dirString);
           // throw new RemoteException("Exception while changing directories" + e.getMessage());
        }
    }

    public Vector list() 
    throws ServerException,ClientException,IOException {
        try {
            return this.gridFTPClient.list();
        } catch(Exception e) {
            throw new RemoteException("Exception when performing list" + e.getMessage());
        }
    }
}
