package org.globus.ogsa.impl.base.multirft.util;

import org.globus.ftp.GridFTPClient;

import java.util.StringTokenizer;
import java.util.Vector;
import java.io.IOException;
import java.rmi.RemoteException;
import org.globus.ftp.exception.ServerException;
import org.globus.ftp.exception.ClientException;
import org.globus.ftp.exception.UnexpectedReplyCodeException;

public class FileSystemUtil {

    GridFTPClient gridFTPClient = null;
    
    public void setGridFTPClient(GridFTPClient gridFTPClient) {
        this.gridFTPClient = gridFTPClient;
    }
    
    /* this method takes a string which has a set of directories
    *   that are delimited by / 
    */
    public void makeDirectory(String dir)
    throws IOException,ServerException {
        try {
                this.gridFTPClient.makeDir(dir);
            
        } catch(ServerException e) {
            System.out.println("Error Code : " + ((UnexpectedReplyCodeException)(e.getRootCause())).getReply().getCode());
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
