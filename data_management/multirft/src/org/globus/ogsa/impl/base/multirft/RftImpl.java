/*This file is licensed under the terms of the Globus Toolkit Public|License, found at http://www.globus.org/toolkit/download/license.html.*/
package org.globus.ogsa.impl.base.multirft;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import java.net.MalformedURLException;
import java.net.URL;

import java.rmi.RemoteException;

import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import javax.security.auth.Subject;

import javax.xml.namespace.QName;

import org.apache.axis.MessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.axis.gsi.GSIConstants;

import org.globus.gsi.jaas.JaasGssUtil;

import org.globus.ogsa.GridConstants;
import org.globus.ogsa.GridContext;
import org.globus.ogsa.GridServiceException;
import org.globus.ogsa.ServiceData;
import org.globus.ogsa.ServiceProperties;
import org.globus.ogsa.base.multirft.FileTransferJobStatusType;

//import org.gridforum.ogsi.ServiceLocatorType;
import org.globus.ogsa.base.multirft.FileTransferProgressType;
import org.globus.ogsa.base.multirft.FileTransferRestartMarker;
import org.globus.ogsa.base.multirft.FileTransferStatusElement;
import org.globus.ogsa.base.multirft.GridFTPPerfMarkerElement;
import org.globus.ogsa.base.multirft.GridFTPPerfMarkerType;
import org.globus.ogsa.base.multirft.GridFTPRestartMarkerElement;
import org.globus.ogsa.base.multirft.GridFTPRestartMarkerType;
import org.globus.ogsa.base.multirft.RFTOptionsType;
import org.globus.ogsa.base.multirft.RFTPortType;
import org.globus.ogsa.base.multirft.TransferRequestElement;
import org.globus.ogsa.base.multirft.TransferRequestType;
import org.globus.ogsa.base.multirft.TransferStatusType;
import org.globus.ogsa.base.multirft.TransferType;
import org.globus.ogsa.base.multirft.Version;
import org.globus.ogsa.config.ConfigException;
import org.globus.ogsa.config.ContainerConfig;
import org.globus.ogsa.impl.base.multirft.TransferDbAdapter;
import org.globus.ogsa.impl.base.multirft.TransferDbOptions;
import org.globus.ogsa.impl.base.multirft.TransferJob;
import org.globus.ogsa.impl.core.handle.HandleHelper;
import org.globus.ogsa.impl.ogsi.GridServiceImpl;
import org.globus.ogsa.impl.security.SecurityManager;
import org.globus.ogsa.impl.security.authentication.Constants;
import org.globus.ogsa.impl.security.authentication.SecContext;
import org.globus.ogsa.impl.security.authentication.SecureServicePropertiesHelper;
import org.globus.ogsa.impl.security.authorization.SelfAuthorization;
import org.globus.ogsa.utils.AnyHelper;
import org.globus.ogsa.utils.MessageUtils;
import org.globus.ogsa.wsdl.GSR;

import org.globus.util.GlobusURL;
import org.globus.util.Util;

import org.gridforum.ogsi.ServiceDataType;

import org.ietf.jgss.GSSCredential;

import org.w3c.dom.Document;
import org.w3c.dom.Element;


public class RftImpl
    extends GridServiceImpl {

    static Log logger = LogFactory.getLog(RftImpl.class.getName());
    String configPath;
    TransferRequestType transferRequest;
    TransferRequestElement transferRequestElement;
    TransferType[] transfers;
    private Map notifyProps;
    int concurrency;
    int maxAttempts = 10;
    TransferDbAdapter dbAdapter;
    TransferDbOptions dbOptions;
    ServiceData transferProgressData;
    ServiceData restartMarkerServiceData;
    ServiceData requestStatusData;
    ServiceData singleFileTransferStatusSDE;
    ServiceData gridFTPRestartMarkerSD;
    ServiceData gridFTPPerfMarkerSD;
    ServiceData versionSD;
    FileTransferProgressType transferProgress;
    FileTransferRestartMarker restartMarkerDataType;
    FileTransferStatusElement[] fileTransferStatusElements;
    FileTransferStatusElement fileTransferStatusElement;
    FileTransferJobStatusType[] statusTypes;
    GridFTPRestartMarkerElement gridFTPRestartMarkerSDE;
    GridFTPPerfMarkerElement gridFTPPerfMarkerSDE;
    Version version;
    int requestId = -1;
    private int persistentRequestId = 0;
    private int requestId_ = 0;
    private int transferJobId_ = 0;
    private boolean check = false; // check to update transferids of Status SDEs
    Vector activeTransferThreads;
    Vector transferClients;
    RFTOptionsType globalRFTOptionsType;

    public RftImpl() {
        super("MultifileRFTService");
        this.transferRequest = null;
    }

    public RftImpl(TransferRequestType transferRequest) {
        super("MultifileRFTService");

        String name = "MultifileRFTService";

        this.transferRequest = transferRequest;
        this.globalRFTOptionsType=transferRequest.getRftOptions();

        if (transferRequest == null) {
            logger.debug("transfer request is null");
        }
    }

    /**
     * DOCUMENT ME!
     * 
     * @return DOCUMENT ME! 
     * @throws RemoteException DOCUMENT ME!
     */
    public int start()
              throws RemoteException {

        Subject subject = SecurityManager.getManager().setServiceOwnerFromContext(
                                  this);
        GSSCredential cred = JaasGssUtil.getCredential(subject);

        if (cred == null) {
            throw new RemoteException("Delegation not performed");
        }

        try {

            String path = TransferClient.saveCredential(cred);
            Util.setFilePermissions(path, 600);
            logger.debug("Credential saved at : " + path);
            logger.debug(
                    "Got a credential with Subject: " + 
                    cred.getName().toString());
            dbAdapter.storeProxyLocation(requestId, path);

            int temp = 0;

            while (temp < concurrency) {

                TransferJob transferJob = new TransferJob(transfers[temp], 
                                                          TransferJob.STATUS_PENDING, 
                                                          0);
                TransferThread transferThread = new TransferThread(transferJob);
                transferThread.start();
                activeTransferThreads.add(transferThread);
                temp = temp + 1;
            }
        } catch (Exception e) {
            logger.error("Error in start " + e.toString(), e);
            throw new RemoteException(MessageUtils.toString(e));
        }

        return requestId;
    }

    /**
     * DOCUMENT ME!
     * 
     * @param requestId DOCUMENT ME!
     * @param fromId DOCUMENT ME!
     * @param toId DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public void cancel(int requestId, int fromId, int toId)
                throws RemoteException {
        logger.debug("Cancelling transfers of the request: " + requestId);
        logger.debug("from id: " + fromId + "to id: " + toId);
        dbAdapter.cancelTransfers(requestId, fromId, toId);
        cancelActiveTransfers(fromId, toId);
    }

    /**
     * DOCUMENT ME!
     * 
     * @param fromId DOCUMENT ME!
     * @param toId DOCUMENT ME!
     * @throws RftDBException DOCUMENT ME!
     */
    public void cancelActiveTransfers(int fromId, int toId)
                               throws RftDBException {

        for (int i = fromId; i <= toId; i++) {

            TransferThread tempTransferThread = (TransferThread)activeTransferThreads.elementAt(
                                                        i);
            tempTransferThread.killThread();
        }
    }

    /**
     * DOCUMENT ME!
     */
    private void notifyUpdate() {
        logger.debug("Notifying Update");
    }

    /**
     * DOCUMENT ME!
     * 
     * @param messageContext DOCUMENT ME!
     * @throws GridServiceException DOCUMENT ME!
     */
    public void postCreate(GridContext messageContext)
                    throws GridServiceException {

        try {
            super.postCreate(messageContext);
            logger.debug("In postCreate");

            ServiceProperties factoryProperties = (ServiceProperties)getProperty(
                                                          ServiceProperties.FACTORY);
            transferProgress = new FileTransferProgressType();
            restartMarkerDataType = new FileTransferRestartMarker();
            fileTransferStatusElement = new FileTransferStatusElement();
            gridFTPRestartMarkerSDE = new GridFTPRestartMarkerElement();
            gridFTPPerfMarkerSDE = new GridFTPPerfMarkerElement();
            version = new Version();
            this.requestStatusData = this.serviceData.create(
                                             "FileTransferStatus");
            this.transferProgressData = this.serviceData.create(
                                                "FileTransferProgress");
            this.singleFileTransferStatusSDE = this.serviceData.create(
                                                       "SingleFileTransferStatus");
            this.restartMarkerServiceData = this.serviceData.create(
                                                    "FileTransferRestartMarker");
            this.gridFTPRestartMarkerSD = this.serviceData.create(
                                                  "GridFTPRestartMarker");
            this.gridFTPPerfMarkerSD = this.serviceData.create(
                                               "GridFTPPerfMarker");
            this.versionSD = this.serviceData.create("MultiRFTVersion");
            this.version.setVersion("1.0");
            this.versionSD.setValue(this.version);
            this.serviceData.add(this.versionSD);

            int progressInt = 0;
            this.transferProgress.setPercentComplete(progressInt);
            this.transferProgressData.setValue(transferProgress);
            this.serviceData.add(transferProgressData);
            this.restartMarkerDataType.setRestartMarkerRange(progressInt);
            this.restartMarkerServiceData.setValue(restartMarkerDataType);
            this.serviceData.add(restartMarkerServiceData);

            FileTransferJobStatusType statusType = new FileTransferJobStatusType();
            statusType.setTransferId(-1);
            statusType.setDestinationUrl("destURLPlaceHolder");
            statusType.setStatus(null);
            fileTransferStatusElement.setRequestStatus(statusType);
            this.singleFileTransferStatusSDE.setValue(
                    fileTransferStatusElement);
            this.serviceData.add(singleFileTransferStatusSDE);
            gridFTPRestartMarkerSDE.setGridFTPRestartMarker(new GridFTPRestartMarkerType());
            this.gridFTPRestartMarkerSD.setValue(this.gridFTPRestartMarkerSDE);
            this.serviceData.add(this.gridFTPRestartMarkerSD);
            gridFTPPerfMarkerSDE.setGridFTPPerfMarker(new GridFTPPerfMarkerType());
            this.gridFTPPerfMarkerSD.setValue(this.gridFTPPerfMarkerSDE);
            this.serviceData.add(this.gridFTPPerfMarkerSD);

            String persistentRequestIdString = (String)getPersistentProperty(
                                                       "requestId");
            String temp = (String)factoryProperties.getProperty("maxAttempts");
            int maxAttempts = Integer.parseInt(temp);
            String jdbcDriver = (String)factoryProperties.getProperty(
                                        "JdbcDriver");
            String connectionURL = (String)factoryProperties.getProperty(
                                           "connectionURL");
            String userName = (String)factoryProperties.getProperty(
                                      "dbusername");
            String password = (String)factoryProperties.getProperty("password");
            dbOptions = new TransferDbOptions(jdbcDriver, connectionURL, 
                                              userName, password);
            dbAdapter = TransferDbAdapter.setupDBConnection(dbOptions);
            activeTransferThreads = new Vector();
            transferClients = new Vector();

            if (persistentRequestIdString != null) {
                logger.debug(
                        "recovering transfer request: " + 
                        persistentRequestIdString);
                this.persistentRequestId = Integer.parseInt(
                                                   persistentRequestIdString);
                this.requestId = this.persistentRequestId;

                String proxyLocation = dbAdapter.getProxyLocation(
                                               this.persistentRequestId);
                GSSCredential credential = TransferClient.loadCredential(
                                                   proxyLocation);
                setNotifyProps(credential, Constants.ENCRYPTION);

                Vector recoveredTransferJobs = dbAdapter.getActiveTransfers(
                                                       persistentRequestId);
                int tempSize = recoveredTransferJobs.size();
                transfers = new TransferType[tempSize];

                for (int i = 0; i < tempSize; i++) {

                    TransferJob transferJob = (TransferJob)recoveredTransferJobs.elementAt(
                                                      i);

                    //converting recovered transfers to transfer types
                    transfers[i] = new TransferType();
                   // transfers[i].setTransferId(transferJob.getTransferId());
                    transfers[i].setSourceUrl(transferJob.getSourceUrl());
                    transfers[i].setDestinationUrl(transferJob.getDestinationUrl());
                    transfers[i].setRftOptions(transferJob.getRftOptions());
                }

                int concurrency_ = dbAdapter.getConcurrency(
                                           this.persistentRequestId);
                logger.debug(
                        "Concurrency of recovered request: " + concurrency_);
                logger.debug("Populating FileTransferStatus SDEs");
                fileTransferStatusElements = new FileTransferStatusElement[transfers.length];
                statusTypes = new FileTransferJobStatusType[transfers.length];

                // transferJobId_ = dbAdapter.getTransferJobId(requestId);
                for (int i = 0; i < transfers.length; i++) {
                    statusTypes[i] = new FileTransferJobStatusType();
                    statusTypes[i].setTransferId(transfers[i].getTransferId());
                    statusTypes[i].setDestinationUrl(transfers[i].getDestinationUrl());
                    statusTypes[i].setStatus(mapStatus(TransferJob.STATUS_PENDING));
                    fileTransferStatusElements[i] = new FileTransferStatusElement();
                    fileTransferStatusElements[i].setRequestStatus(
                            statusTypes[i]);
                }

                requestStatusData.setValues(
                        new Object[] { fileTransferStatusElements });
                this.serviceData.add(requestStatusData);

                for (int i = 0; i < concurrency_; i++) {

                    TransferJob transferJob = (TransferJob)recoveredTransferJobs.elementAt(
                                                      i);
                    int tempStatus = transferJob.getStatus();

                    if ((tempStatus == TransferJob.STATUS_ACTIVE) || 
                        (tempStatus == TransferJob.STATUS_PENDING)) {

                        TransferThread transferThread = new TransferThread(
                                                                transferJob);
                        logger.debug("Starting recovered transfer jobs ");
                        transferThread.start();
                    }
                }
            } else {
                SecurityManager manager = SecurityManager.getManager();

                GSSCredential cred = SecureServicePropertiesHelper.getCredential(
                                             this);
                transfers = this.transferRequest.getTransferArray();
                this.concurrency = transferRequest.getConcurrency();
                requestId = dbAdapter.storeTransferRequest(
                                    this.transferRequest);
                setPersistentProperty("requestId", Integer.toString(requestId));
                setPersistentProperty("activateOnStartup", 
                                      Boolean.TRUE.toString());
                flush();
                this.persistentRequestId = requestId;
                logger.debug("Populating FileTransferStatus SDEs");
                fileTransferStatusElements = new FileTransferStatusElement[transfers.length];
                statusTypes = new FileTransferJobStatusType[transfers.length];
                transferJobId_ = dbAdapter.getTransferJobId(requestId);
                logger.debug(
                        "setting transferid in statusTypes to : " + 
                        transferJobId_);

                for (int i = 0; i < transfers.length; i++) {
                    statusTypes[i] = new FileTransferJobStatusType();
                    statusTypes[i].setTransferId(transferJobId_++);
                    statusTypes[i].setDestinationUrl(transfers[i].getDestinationUrl());
                    statusTypes[i].setStatus(mapStatus(TransferJob.STATUS_PENDING));
                    fileTransferStatusElements[i] = new FileTransferStatusElement();
                    fileTransferStatusElements[i].setRequestStatus(
                            statusTypes[i]);
                }

                requestStatusData.setValues(
                        new Object[] { fileTransferStatusElements });
                this.serviceData.add(requestStatusData);
            }
        } catch (Exception e) {
            throw new GridServiceException(e);
        }
    }

    /**
     * DOCUMENT ME!
     * 
     * @param transferStatus DOCUMENT ME!
     * @return DOCUMENT ME! 
     */
    private TransferStatusType mapStatus(int transferStatus) {

        if (transferStatus == 0) {

            return TransferStatusType.Finished;
        }

        if (transferStatus == 1) {

            return TransferStatusType.Retrying;
        }

        if (transferStatus == 2) {

            return TransferStatusType.Failed;
        }

        if (transferStatus == 3) {

            return TransferStatusType.Active;
        }

        if (transferStatus == 4) {

            return TransferStatusType.Pending;
        }

        if (transferStatus == 5) {

            return TransferStatusType.Cancelled;
        }

        return null;
    }

    /**
     * DOCUMENT ME!
     * 
     * @param credential DOCUMENT ME!
     * @param msgProt DOCUMENT ME!
     */
    private void setNotifyProps(GSSCredential credential, Object msgProt) {
        this.notifyProps = new HashMap();
        this.notifyProps.put(GSIConstants.GSI_MODE, 
                             GSIConstants.GSI_MODE_NO_DELEG);
        this.notifyProps.put(Constants.GSI_SEC_CONV, msgProt);
        this.notifyProps.put(Constants.AUTHORIZATION, 
                             SelfAuthorization.getInstance());
        this.notifyProps.put(GSIConstants.GSI_CREDENTIALS, credential);
    }

    /**
     * DOCUMENT ME!
     * 
     * @throws Exception DOCUMENT ME!
     */
    public void preDestroy(GridContext context) 
    throws GridServiceException {
        super.preDestroy(context);
        logger.debug("RFT instance destroyed");
    }

    /**
     * DOCUMENT ME!
     * 
     * @param transferJob DOCUMENT ME!
     * @throws GridServiceException DOCUMENT ME!
     */
    public void statusChanged(TransferJob transferJob)
                       throws GridServiceException {
        logger.debug("Single File Transfer Status SDE changed "+transferJob.getStatus());
        dbAdapter.update(transferJob);
        transferJobId_ = transferJob.getTransferId();

        FileTransferJobStatusType statusType = new FileTransferJobStatusType();
        statusType.setTransferId(transferJob.getTransferId());
        statusType.setDestinationUrl(transferJob.getDestinationUrl());
        statusType.setStatus(mapStatus(transferJob.getStatus()));
        this.fileTransferStatusElement.setRequestStatus(statusType);
        this.singleFileTransferStatusSDE.setValue(fileTransferStatusElement);
        this.serviceData.add(singleFileTransferStatusSDE);
        singleFileTransferStatusSDE.notifyChange();

        for (int i = 0; i < transfers.length; i++) {

            if (statusTypes[i].getTransferId() == transferJob.getTransferId()) {
                statusTypes[i].setStatus(mapStatus(transferJob.getStatus()));
            }
        }
    }

    public TransferClient getTransferClient(String sourceURL,String destinationURL) 
    throws MalformedURLException  {
        TransferClient transferClient = null;
        boolean flag=false;
        logger.debug("Inside getTransferClient"+this.transferClients.size());
        for(int i=0;i<this.transferClients.size();i++) {
            TransferClient tempTransferClient = (TransferClient) this.transferClients.elementAt(i);
            GlobusURL source = tempTransferClient.getSourceURL();
            GlobusURL destination = tempTransferClient.getDestinationURL();
            int status = tempTransferClient.getStatus();
            GlobusURL tempSource = new GlobusURL(sourceURL);
            GlobusURL tempDest = new GlobusURL(destinationURL);
            if((status==0) || (status==2)) {
                flag=true;
            }
            if((source.getHost().equals(tempSource.getHost())) && (destination.getHost().equals(tempDest.getHost())) && flag) { 
                transferClient = tempTransferClient;
                transferClient.setSourcePath(tempSource.getPath());
                transferClient.setDestinationPath(tempDest.getPath());
                logger.debug("status: " + status);
                return transferClient;
            }
        }
        return transferClient;
    }
            
    public class TransferThread
        extends Thread {

        TransferJob transferJob;
        TransferClient transferClient;
        int status;
        int attempts;
        BufferedReader stdInput;
        BufferedReader stdError;

        TransferThread(TransferJob transferJob) {
            this.transferJob = transferJob;
            this.attempts = transferJob.getAttempts();
            this.status = transferJob.getStatus();
        }
        public void setTransferClient(TransferClient transferClient) {
            this.transferClient = transferClient;
        }

        /**
         * DOCUMENT ME!
         * 
         * @throws RftDBException DOCUMENT ME!
         */
        public void killThread()
                        throws RftDBException {
            transferJob.setStatus(TransferJob.STATUS_CANCELLED);
            dbAdapter.update(transferJob);
        }

        /**
         * DOCUMENT ME!
         */
        public void run() {

            try {

                int tempId = transferJob.getTransferId();
                TransferThread transferThread;
                RFTOptionsType rftOptions = transferJob.getRftOptions();
                if(rftOptions==null) {
                    logger.debug("Setting globalRFTOptions");
                    rftOptions = globalRFTOptionsType;
                }
                String proxyLocation = dbAdapter.getProxyLocation(requestId);
                logger.debug(
                        "Proxy location" + proxyLocation + " " + requestId);

                try {
                    logger.debug("in run");
                    transferClient = getTransferClient(transferJob.getSourceUrl(),
                    transferJob.getDestinationUrl());
                    
                    if(transferClient==null) {
                    logger.debug("No transferClient in the pool");
                    transferClient = new TransferClient(tempId, 
                                                        transferJob.getSourceUrl(), 
                                                        transferJob.getDestinationUrl(), 
                                                        proxyLocation, 
                                                        dbOptions, 
                                                        transferProgress, 
                                                        serviceData, 
                                                        transferProgressData, 
                                                        restartMarkerServiceData, 
                                                        restartMarkerDataType, 
                                                        gridFTPRestartMarkerSD, 
                                                        gridFTPRestartMarkerSDE, 
                                                        gridFTPPerfMarkerSD, 
                                                        gridFTPPerfMarkerSDE, 
                                                        rftOptions);
                    } else {
                        logger.debug("Reusing TransferClient from the pool");
                        transferClient.setSourceURL(transferJob.getSourceUrl());
                        transferClient.setDestinationURL(transferJob.getDestinationUrl());
                        transferClient.setStatus(TransferJob.STATUS_ACTIVE);
                    }
                } catch (Exception e) {
                    logger.error("Error in Transfer Client" + e.toString(), e);
                    transferJob.setStatus(TransferJob.STATUS_FAILED);
                    statusChanged(transferJob);
                    notifyUpdate();

                    TransferJob newTransferJob = dbAdapter.getTransferJob(
                                                         requestId);

                    if (newTransferJob != null) {
                        transferThread = new TransferThread(newTransferJob);
                        logger.debug(
                                "Attempts in new transfer: " + 
                                newTransferJob.getAttempts());
                        transferThread.start();
                        newTransferJob.setStatus(TransferJob.STATUS_ACTIVE);
                        notifyUpdate();
                        statusChanged(newTransferJob);
                    } else {
                        logger.debug("No more transfers ");
                    }

                    throw new RemoteException(MessageUtils.toString(e));
                }

                String restartMarker = dbAdapter.getRestartMarker(tempId);

                if (restartMarker != null) {
                    transferClient.setRestartMarker(restartMarker);

                }

                if (transferClient != null) {
                    transferClient.setStatus(TransferJob.STATUS_ACTIVE);
                    transferClient.setParallelStreams(rftOptions.getParallelStreams());
                    transferClient.setTcpBufferSize(rftOptions.getTcpBufferSize());
                    transferClient.setRFTOptions(rftOptions);
                    transferClient.transfer();
                    transferJob.setStatus(TransferJob.STATUS_ACTIVE);
                    dbAdapter.update(transferJob);
                    transferJob.setStatus(transferClient.getStatus());
                    statusChanged(transferJob);

                    int x = transferClient.getStatus();
                    transferJob.setAttempts(transferJob.getAttempts() + 1);

                    if (x == 0) {
                        transferJob.setStatus(TransferJob.STATUS_FINISHED);
                        this.status = TransferJob.STATUS_FINISHED;
                        notifyUpdate();
                        statusChanged(transferJob);
                        transferProgress.setPercentComplete(100);
                        transferProgressData.setValue(transferProgress);
                        transferClient.setStatus(TransferJob.STATUS_FINISHED);
                        transferClients.add(transferClient);
                    } else if ((x == 1) && 
                               (transferJob.getAttempts() < maxAttempts)) {
                        transferJob.setStatus(TransferJob.STATUS_PENDING);
                        transferClient.setStatus(TransferJob.STATUS_PENDING);
                        this.status = TransferJob.STATUS_PENDING;
                        notifyUpdate();
                        statusChanged(transferJob);

                        /*     transferThread = new TransferThread(transferJob);
                               transferThread.start();
                               transferJob.setStatus(TransferJob.STATUS_ACTIVE);
                               notifyUpdate(); */
                    } else if ((x == 2) || 
                               (transferJob.getAttempts() >= maxAttempts)) {
                        transferJob.setStatus(TransferJob.STATUS_FAILED);
                        this.status = TransferJob.STATUS_FAILED;
                        statusChanged(transferJob);
                        transferClient.setStatus(TransferJob.STATUS_FAILED);
                        transferClients.add(transferClient);
                    } else {
                        transferJob.setStatus(TransferJob.STATUS_RETRYING);
                        transferClient.setStatus(TransferJob.STATUS_RETRYING);
                        this.status= TransferJob.STATUS_RETRYING;
                        notifyUpdate();
                        statusChanged(transferJob);
                    }
                } else {
                    transferJob.setStatus(TransferJob.STATUS_FAILED);
                    this.status = TransferJob.STATUS_FAILED;
                    statusChanged(transferJob);
                    transferClient.setStatus(TransferJob.STATUS_FAILED);
                    transferClients.add(transferClient);
                }

                dbAdapter.update(transferJob);

                TransferJob newTransferJob = dbAdapter.getTransferJob(
                                                     requestId);
                logger.debug("starting a new transfer");

                if (newTransferJob != null) {
                    transferThread = new TransferThread(newTransferJob);
                    logger.debug(
                            "Attempts in new transfer: " + 
                            newTransferJob.getAttempts());
                    transferThread.start();
                    newTransferJob.setStatus(TransferJob.STATUS_ACTIVE);
                    notifyUpdate();
                    statusChanged(newTransferJob);
                } else {
                    logger.debug("No more transfers ");
                }
            } catch (Exception ioe) {
                logger.error("Error in Transfer Thread" + ioe.toString(), ioe);
            }
             catch (Throwable ee) {
                logger.error("Error in Transfer Thread" + ee.toString(), ee);
            }
        }
    }
}
