/*This file is licensed under the terms of the Globus Toolkit Public|License, found at http://www.globus.org/toolkit/download/license.html.*/
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
import org.globus.ogsa.utils.MessageUtils;

import org.globus.util.GlobusURL;

import org.gridforum.jgss.ExtendedGSSCredential;
import org.gridforum.jgss.ExtendedGSSManager;

import org.gridforum.ogsi.ServiceDataType;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;


public class TransferClient {

    GridFTPClient sourceHost;
    GridFTPClient destinationHost;
    String sourcePath;
    String destinationPath;
    String proxyPath;
    String sourceHostName;
    String destinationHostName;
    int status=-1;
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
    private static Logger logger = Logger.getLogger(TransferClient.class.getName());

    public TransferClient() {
    }
    public void setSourceURL(String sourceURL)
    throws RemoteException {
        try {
            this.sourceGlobusURL = new GlobusURL(sourceURL);
        } catch(Exception e) {
            status=2;
            logger.debug("Invalid Source URL");
            throw new RemoteException(MessageUtils.toString(e));
        }
    }
    public void setDestinationURL(String destinationURL) 
    throws RemoteException {
        try {
            this.destinationGlobusURL = new GlobusURL(destinationURL);
        } catch(Exception e) {
            status=2;
            logger.debug("Invalid Destination URL"); 
            throw new RemoteException(MessageUtils.toString(e));
        }
    }
    public GlobusURL getSourceURL() {
        return this.sourceGlobusURL;
    }
    public GlobusURL getDestinationURL() {
        return this.destinationGlobusURL;
    }
    public void setSourceHost(String sourceURL)
    throws RemoteException {
        try {
            this.sourceGlobusURL = new GlobusURL(sourceURL);
            this.sourceHost = new GridFTPClient(this.sourceGlobusURL.getHost(),
                                            this.sourceGlobusURL.getPort());
        } catch(Exception e) {
            status=2;
            logger.debug("Unable to create GridFTP Client to : " + this.sourceGlobusURL.getHost());
            throw new RemoteException(MessageUtils.toString(e));
        }
    }
    public void setDestinationHost(String destURL)
    throws RemoteException {
        try {
            this.destinationGlobusURL = new GlobusURL(destURL);
            this.destinationHost = new GridFTPClient(this.destinationGlobusURL.getHost(),
                                            this.destinationGlobusURL.getPort());
        } catch(Exception e) {
            status=2;
            logger.debug("Unable to create GridFTP Client to : " + this.destinationGlobusURL.getHost());
            throw new RemoteException(MessageUtils.toString(e));
        }
    }
    public void setStatus(int status) {
        this.status = status;
    }
    public void setCredential(String proxyPath) 
    throws org.ietf.jgss.GSSException {
        this.credential = loadCredential(proxyPath);
    } 
    public void initialize()
    throws RemoteException {
        try {
            setTransferParams(this.destinationHost,this.credential);
            setTransferParams(this.sourceHost,this.credential);
            this.size = this.sourceHost.getSize(this.sourcePath);
        } catch(Exception e) {
            throw new RemoteException(MessageUtils.toString(e));
        }
    }
        
    public void setTransferId(int transferId) {
        this.transferid= transferId;
    }
    public void setRftOptions(RFTOptionsType rftOptions) {
        this.rftOptions = rftOptions;
    }
    public void setDbOptions(TransferDbOptions dbOptions) {
        this.dbOptions = dbOptions;
    }
    public void setMyMarkerListener(FileTransferProgressType transferProgress,
                                    ServiceDataSet serviceData, 
                                    ServiceData transferProgressData, 
                                    ServiceData restartMarkerServiceData, 
                                    FileTransferRestartMarker restartMarker, 
                                    ServiceData gridFTPRestartMarkerSD, 
                                    GridFTPRestartMarkerElement gridFTPRestartMarkerElement, 
                                    ServiceData gridFTPPerfMarkerSD, 
                                    GridFTPPerfMarkerElement gridFTPPerfMarkerElement) {
        this.markerListener = new MyMarkerListener(this.dbOptions,transferProgress,
                                                    serviceData,transferProgressData,this.size,
                                                    restartMarkerServiceData,restartMarker,
                                                    gridFTPRestartMarkerSD,gridFTPRestartMarkerElement,
                                                    gridFTPPerfMarkerSD,gridFTPPerfMarkerElement);
        this.markerListener.setTransferId(this.transferid);
    }

    public void setAuthorization() {
        subjectName = this.rftOptions.getSubjectName();
        sourceSubjectName = this.rftOptions.getSourceSubjectName();
        destinationSubjectName = this.rftOptions.getDestinationSubjectName();

        if (subjectName != null) {
            destinationHost.setAuthorization(new IdentityAuthorization(
                                                         subjectName));
            sourceHost.setAuthorization(new IdentityAuthorization(
                                                    subjectName));
        }
        if (sourceSubjectName != null) {
            sourceHost.setAuthorization(new IdentityAuthorization(
                                                    sourceSubjectName));
        }

        if (destinationSubjectName != null) {
            destinationHost.setAuthorization(new IdentityAuthorization(
                                                         destinationSubjectName));
        }
    }
    public TransferClient(int transferid, String sourceURL, 
                          String destinationURL, String proxyPath, 
                          TransferDbOptions dbOptions, 
                          FileTransferProgressType transferProgress, 
                          ServiceDataSet serviceData, 
                          ServiceData transferProgressData, 
                          ServiceData restartMarkerServiceData, 
                          FileTransferRestartMarker restartMarker, 
                          ServiceData gridFTPRestartMarkerSD, 
                          GridFTPRestartMarkerElement gridFTPRestartMarkerElement, 
                          ServiceData gridFTPPerfMarkerSD, 
                          GridFTPPerfMarkerElement gridFTPPerfMarkerElement, 
                          RFTOptionsType rftOptions)
                   throws RemoteException {

        try {
            this.transferid = transferid;
            sourceGlobusURL = new GlobusURL(sourceURL);
            destinationGlobusURL = new GlobusURL(destinationURL);
            sourceHostName = sourceGlobusURL.getHost();
            destinationHostName = destinationGlobusURL.getHost();
            sourcePath = "/" + sourceGlobusURL.getPath();
            destinationPath = "/" + destinationGlobusURL.getPath();
            sourcePort = sourceGlobusURL.getPort();
            destinationPort = destinationGlobusURL.getPort();
            sourceHost = new GridFTPClient(sourceGlobusURL.getHost(), 
                                           sourceGlobusURL.getPort());
            destinationHost = new GridFTPClient(destinationGlobusURL.getHost(), 
                                                destinationGlobusURL.getPort());
            this.credential = loadCredential(proxyPath);
            this.rftOptions = rftOptions;
            subjectName = this.rftOptions.getSubjectName();
            sourceSubjectName = this.rftOptions.getSourceSubjectName();
            destinationSubjectName = this.rftOptions.getDestinationSubjectName();

            if (subjectName != null) {
                destinationHost.setAuthorization(new IdentityAuthorization(
                                                         subjectName));
                sourceHost.setAuthorization(new IdentityAuthorization(
                                                    subjectName));
            }

            if (sourceSubjectName != null) {
                sourceHost.setAuthorization(new IdentityAuthorization(
                                                    sourceSubjectName));
            }

            if (destinationSubjectName != null) {
                destinationHost.setAuthorization(new IdentityAuthorization(
                                                         destinationSubjectName));
            }

            setTransferParams(destinationHost, this.credential);
            setTransferParams(sourceHost, this.credential);
            size = sourceHost.getSize(sourcePath);
            markerListener = new MyMarkerListener(dbOptions, transferProgress, 
                                                  serviceData, 
                                                  transferProgressData, size, 
                                                  restartMarkerServiceData, 
                                                  restartMarker, 
                                                  gridFTPRestartMarkerSD, 
                                                  gridFTPRestartMarkerElement, 
                                                  gridFTPPerfMarkerSD, 
                                                  gridFTPPerfMarkerElement);
            markerListener.setTransferId(transferid);
            logger.debug("Transfer Id in TransferClient : " + transferid);
        } catch (MalformedURLException mue) {
            status = 2;
            logger.error("Error in TransferClient:Invalid URLs", mue);
        }
         catch (Exception e) {
            status = 2;
            logger.error("Error in TransferClient", e);
            throw new RemoteException(MessageUtils.toString(e));
        }
    }

    /**
     * DOCUMENT ME!
     * 
     * @param credPath DOCUMENT ME!
     * @return DOCUMENT ME! 
     * @throws GSSException DOCUMENT ME!
     */
    public static GSSCredential loadCredential(String credPath)
                                        throws GSSException {

        ExtendedGSSManager manager = (ExtendedGSSManager)ExtendedGSSManager.getInstance();
        String handle = "X509_USER_PROXY=" + credPath;

        return manager.createCredential(handle.getBytes(), 
                                        ExtendedGSSCredential.IMPEXP_MECH_SPECIFIC, 
                                        GSSCredential.DEFAULT_LIFETIME, null, 
                                        GSSCredential.INITIATE_AND_ACCEPT);
    }

    /**
     * DOCUMENT ME!
     * 
     * @param credential DOCUMENT ME!
     * @return DOCUMENT ME! 
     * @throws GSSException DOCUMENT ME!
     */
    public static String saveCredential(GSSCredential credential)
                                 throws GSSException {

        if (!(credential instanceof ExtendedGSSCredential)) {
            throw new GSSException(GSSException.FAILURE);
        }

        ExtendedGSSManager manager = (ExtendedGSSManager)ExtendedGSSManager.getInstance();
        byte[] buf = ((ExtendedGSSCredential)credential).export(
                             ExtendedGSSCredential.IMPEXP_MECH_SPECIFIC);

        if (buf == null) {
            throw new GSSException(GSSException.FAILURE);
        }

        String handle = new String(buf);
        int pos = handle.indexOf('=');

        if (pos == -1) {
            throw new GSSException(GSSException.FAILURE);
        }

        return handle.substring(pos + 1).trim();
    }

    /**
     * DOCUMENT ME!
     * 
     * @param proxyPath DOCUMENT ME!
     */
    public void setProxyPath(String proxyPath) {
        this.proxyPath = proxyPath;
    }

    /**
     * DOCUMENT ME!
     * 
     * @param host DOCUMENT ME!
     */
    public void setSource(GridFTPClient host) {
        this.sourceHost = host;
    }

    /**
     * DOCUMENT ME!
     * 
     * @return DOCUMENT ME! 
     */
    public GridFTPClient getSource() {

        return this.sourceHost;
    }

    /**
     * DOCUMENT ME!
     * 
     * @return DOCUMENT ME! 
     */
    public int getStatus() {

        return this.status;
    }

    /**
     * DOCUMENT ME!
     * 
     * @param destinationHost DOCUMENT ME!
     */
    public void setDestination(GridFTPClient destinationHost) {
        this.destinationHost = destinationHost;
    }

    /**
     * DOCUMENT ME!
     * 
     * @return DOCUMENT ME! 
     */
    public GridFTPClient getDestination() {

        return this.destinationHost;
    }

    /**
     * DOCUMENT ME!
     * 
     * @param destPath DOCUMENT ME!
     */
    public void setDestinationPath(String destPath) {
        this.destinationPath = "/" + destPath;
    }

    /**
     * DOCUMENT ME!
     * 
     * @return DOCUMENT ME! 
     */
    public int getTransferID() {

        return this.transferid;
    }

    /**
     * DOCUMENT ME!
     * 
     * @return DOCUMENT ME! 
     */
    public String getDestinationPath() {

        return destinationPath;
    }

    /**
     * DOCUMENT ME!
     * 
     * @param sourcePath DOCUMENT ME!
     */
    public void setSourcePath(String sourcePath) {
        this.sourcePath = "/"+sourcePath;
    }

    /**
     * DOCUMENT ME!
     * 
     * @return DOCUMENT ME! 
     */
    public String getSourcePath() {

        return this.sourcePath;
    }

    /**
     * DOCUMENT ME!
     * 
     * @param rftOptions DOCUMENT ME!
     */
    public void setRFTOptions(RFTOptionsType rftOptions) {
        this.rftOptions = rftOptions;
    }

    /**
     * DOCUMENT ME!
     * 
     * @param host DOCUMENT ME!
     * @param cred DOCUMENT ME!
     */
    public void setTransferParams(GridFTPClient host, GSSCredential cred) {

        try {
            host.authenticate(cred);
            host.setProtectionBufferSize(16384);

            if (rftOptions.isBinary()) {
                host.setType(GridFTPSession.TYPE_IMAGE);
            } else {
                host.setType(GridFTPSession.TYPE_ASCII);
            }

            host.setMode(GridFTPSession.MODE_EBLOCK);

            if (rftOptions.isDcau()) {
                host.setDataChannelAuthentication(
                        DataChannelAuthentication.SELF);
            } else {
                host.setLocalNoDataChannelAuthentication();
            }
        } catch (Exception e) {
            logger.debug("Error in setting Params", e);
            status = 2;

            return;
        }
    }

    /**
     * DOCUMENT ME!
     * 
     * @param marker DOCUMENT ME!
     */
    public void setRestartMarker(String marker) {

        try {
            marker = "Range Marker " + marker;

            GridFTPRestartMarker restartmarker = new GridFTPRestartMarker(
                                                         marker);
            ByteRangeList list = new ByteRangeList();
            list.merge(restartmarker.toVector());
            this.sourceHost.setRestartMarker(list);
        } catch (Exception e) {
            logger.error("Error in setting the restart marker", e);
        }
    }

    /**
     * DOCUMENT ME!
     * 
     * @param parallel DOCUMENT ME!
     */
    public void setParallelStreams(int parallel) {
        this.parallelism = parallel;
    }

    /**
     * DOCUMENT ME!
     * 
     * @param tcpBufferSize DOCUMENT ME!
     */
    public void setTcpBufferSize(int tcpBufferSize) {
        this.tcpBufferSize = tcpBufferSize;
    }

    /**
     * DOCUMENT ME!
     */
    public void transfer() {

        if (rftOptions.isNotpt()) {
            noTptTransfer();
        } else {
            tptTransfer();
        }
    }

    /**
     * DOCUMENT ME!
     */
    private void tptTransfer() {

        try {
            logger.debug("In Transfer Client");
            sourceHost.setOptions(new RetrieveOptions(parallelism));
            sourceHost.setTCPBufferSize(this.tcpBufferSize);
            destinationHost.setTCPBufferSize(this.tcpBufferSize);
            sourceHost.extendedTransfer(this.sourcePath, this.destinationHost, 
                                        this.destinationPath, markerListener);
            status = 0;
        } catch (Exception e) {
            logger.debug("Exception in transfer", e);

            if (status != 2) {
                status = 1;
            }
        }
    }

    /**
     * DOCUMENT ME!
     */
    private void noTptTransfer() {

        try {

            String fullLocalFile = "/tmp/TempGridFTP_" + transferid;
            sourceHost.setOptions(new RetrieveOptions(parallelism));
            sourceHost.setTCPBufferSize(this.tcpBufferSize);

            DataSink sink = null;
            sink = new FileRandomIO(new java.io.RandomAccessFile(fullLocalFile, 
                                                                 "rw"));
            sourceHost.extendedGet(sourcePath, size, sink, markerListener);
            sourceHost.close();
            destinationHost.setOptions(new RetrieveOptions(parallelism));
            destinationHost.setTCPBufferSize(this.tcpBufferSize);

            DataSource source = null;
            source = new FileRandomIO(new java.io.RandomAccessFile(
                                              fullLocalFile, "r"));
            destinationHost.extendedPut(destinationPath, source, 
                                        markerListener);
            destinationHost.close();
            status = 0;
        } catch (FTPException e) {
            logger.debug("Exception in noTpt", e);

            if (status != 2) {
                status = 1;
            }
        }
         catch (IOException ioe) {
            logger.debug("IOException in noTpt", ioe);
        }
    }

    /**
     * DOCUMENT ME!
     * 
     * @param as DOCUMENT ME!
     */
    public static void main(String[] as) {
    }
}
