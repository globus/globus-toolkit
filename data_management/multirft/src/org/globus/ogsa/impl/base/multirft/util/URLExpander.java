package org.globus.ogsa.impl.base.multirft.util;

import org.globus.util.GlobusURL;
import org.globus.ogsa.utils.MessageUtils;
import java.rmi.RemoteException;
import java.util.Vector;
import org.globus.ogsa.impl.base.multirft.TransferJob;


import org.apache.log4j.Logger;

import org.globus.ftp.GridFTPClient;
import org.globus.ftp.GridFTPSession;
import org.globus.ftp.HostPort;
import org.globus.ftp.MlsxEntry;

/**
 *  Description
 *   This class should take  the sourceUrl and destination Url from RftImpl of the Class
 *  and return a Vector of corresponding Fully Qualified gsiftp urls
 *
 * @author     madduri
 * @created    September 28, 2003
 */
public class URLExpander extends Thread {

    TransferJob transferJob;
    GridFTPClient sourceHost, destinationHost;
    GlobusURL sourceURL, destURL;
    String sourcePath, destinationPath;
    FileSystemUtil fileSystemUtil;
    // This transferJob should include directory in source and dest
    private static Logger logger = Logger.getLogger(URLExpander.class.getName());


    /**
     *Constructor for the URLExpander object
     *
     * @param  transferJob          transferJob
     * @exception  RemoteException
     */
    public URLExpander(GridFTPClient sourceHost,GridFTPClient destinationHost, String sourcePath, String destinationPath)
             throws RemoteException {
        try {
            this.sourceHost = sourceHost;
            this.destinationHost = destinationHost;
            this.sourcePath = sourcePath;
            this.destinationPath = destinationPath;
            this.fileSystemUtil = new FileSystemUtil();
            this.fileSystemUtil.setGridFTPClient(this.destinationHost);
        } catch (Exception e) {
            logger.debug("Invalid source/dest urls");
            throw new RemoteException(MessageUtils.toString(e));
        }
    }

    public Vector doMlsd(String sourcePath) 
    throws Exception {
        //this.sourceHost.setType(GridFTPSession.TYPE_ASCII);
        logger.debug("Source Path : " + sourcePath);
        HostPort hp = this.sourceHost.setLocalPassive();
		this.sourceHost.setActive(hp);
        /*this.sourceHost.setType(GridFTPSession.TYPE_IMAGE);
        this.sourceHost.setMode(GridFTPSession.MODE_EBLOCK);*/
        this.sourceHost.changeDir(sourcePath);
        return this.sourceHost.mlsd();
    }
    /**
     *  this invokes  the MLST command from GridFTPClient on the source
     *  hands it over to parser utility which gives set of directories that need to be made
     *  at the destination.Recursive directory traversal or Iterative?
     */
    public void run() {
        try {
            Vector v = doMlsd(this.sourcePath);
            while(!v.isEmpty()) {
                MlsxEntry f = (MlsxEntry)v.remove(0);
                logger.debug(f.toString());
                if(f.get(f.TYPE).equals(f.TYPE_DIR)) {
                    // We have a directory here call this method again
                    // After creating that directory
                    logger.debug("The directory name: " + f.get(MlsxEntry.TYPE_DIR));
                    fileSystemUtil.makeDirectory(f.get("dir"));
                } else if (f.get(f.TYPE).equals(f.TYPE_FILE)) {
                    logger.debug("This is a file : " + f.getFileName());
                }
            }
        } catch(Exception e) {
            logger.error(e.getMessage());
        }
    }
}


