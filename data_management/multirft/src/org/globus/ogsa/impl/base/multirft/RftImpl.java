/*
Globus Toolkit Public License (GTPL)

Copyright (c) 1999 University of Chicago and The University of 
Southern California. All Rights Reserved.

 1) The "Software", below, refers to the Globus Toolkit (in either
    source-code, or binary form and accompanying documentation) and a
    "work based on the Software" means a work based on either the
    Software, on part of the Software, or on any derivative work of
    the Software under copyright law: that is, a work containing all
    or a portion of the Software either verbatim or with
    modifications.  Each licensee is addressed as "you" or "Licensee."

 2) The University of Southern California and the University of
    Chicago as Operator of Argonne National Laboratory are copyright
    holders in the Software.  The copyright holders and their third
    party licensors hereby grant Licensee a royalty-free nonexclusive
    license, subject to the limitations stated herein and
    U.S. Government license rights.

 3) A copy or copies of the Software may be given to others, if you
    meet the following conditions:

    a) Copies in source code must include the copyright notice and
       this license.

    b) Copies in binary form must include the copyright notice and
       this license in the documentation and/or other materials
       provided with the copy.

 4) All advertising materials, journal articles and documentation
    mentioning features derived from or use of the Software must
    display the following acknowledgement:

    "This product includes software developed by and/or derived from
    the Globus project (http://www.globus.org/)."

    In the event that the product being advertised includes an intact
    Globus distribution (with copyright and license included) then
    this clause is waived.

 5) You are encouraged to package modifications to the Software
    separately, as patches to the Software.

 6) You may make modifications to the Software, however, if you
    modify a copy or copies of the Software or any portion of it,
    thus forming a work based on the Software, and give a copy or
    copies of such work to others, either in source code or binary
    form, you must meet the following conditions:

    a) The Software must carry prominent notices stating that you
       changed specified portions of the Software.

    b) The Software must display the following acknowledgement:

       "This product includes software developed by and/or derived
        from the Globus Project (http://www.globus.org/) to which the
        U.S. Government retains certain rights."

 7) You may incorporate the Software or a modified version of the
    Software into a commercial product, if you meet the following
    conditions:

    a) The commercial product or accompanying documentation must
       display the following acknowledgment:

       "This product includes software developed by and/or derived
        from the Globus Project (http://www.globus.org/) to which the
        U.S. Government retains a paid-up, nonexclusive, irrevocable
        worldwide license to reproduce, prepare derivative works, and
        perform publicly and display publicly."

    b) The user of the commercial product must be given the following
       notice:

       "[Commercial product] was prepared, in part, as an account of
        work sponsored by an agency of the United States Government.
        Neither the United States, nor the University of Chicago, nor
        University of Southern California, nor any contributors to
        the Globus Project or Globus Toolkit nor any of their employees,
        makes any warranty express or implied, or assumes any legal
        liability or responsibility for the accuracy, completeness, or
        usefulness of any information, apparatus, product, or process
        disclosed, or represents that its use would not infringe
        privately owned rights.

        IN NO EVENT WILL THE UNITED STATES, THE UNIVERSITY OF CHICAGO
        OR THE UNIVERSITY OF SOUTHERN CALIFORNIA OR ANY CONTRIBUTORS
        TO THE GLOBUS PROJECT OR GLOBUS TOOLKIT BE LIABLE FOR ANY
        DAMAGES, INCLUDING DIRECT, INCIDENTAL, SPECIAL, OR CONSEQUENTIAL
        DAMAGES RESULTING FROM EXERCISE OF THIS LICENSE AGREEMENT OR
        THE USE OF THE [COMMERCIAL PRODUCT]."

 8) LICENSEE AGREES THAT THE EXPORT OF GOODS AND/OR TECHNICAL DATA
    FROM THE UNITED STATES MAY REQUIRE SOME FORM OF EXPORT CONTROL
    LICENSE FROM THE U.S. GOVERNMENT AND THAT FAILURE TO OBTAIN SUCH
    EXPORT CONTROL LICENSE MAY RESULT IN CRIMINAL LIABILITY UNDER U.S.
    LAWS.

 9) Portions of the Software resulted from work developed under a
    U.S. Government contract and are subject to the following license:
    the Government is granted for itself and others acting on its
    behalf a paid-up, nonexclusive, irrevocable worldwide license in
    this computer software to reproduce, prepare derivative works, and
    perform publicly and display publicly.

10) The Software was prepared, in part, as an account of work
    sponsored by an agency of the United States Government.  Neither
    the United States, nor the University of Chicago, nor The
    University of Southern California, nor any contributors to the
    Globus Project or Globus Toolkit, nor any of their employees,
    makes any warranty express or implied, or assumes any legal
    liability or responsibility for the accuracy, completeness, or
    usefulness of any information, apparatus, product, or process
    disclosed, or represents that its use would not infringe privately
    owned rights.

11) IN NO EVENT WILL THE UNITED STATES, THE UNIVERSITY OF CHICAGO OR
    THE UNIVERSITY OF SOUTHERN CALIFORNIA OR ANY CONTRIBUTORS TO THE
    GLOBUS PROJECT OR GLOBUS TOOLKIT BE LIABLE FOR ANY DAMAGES,
    INCLUDING DIRECT, INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES
    RESULTING FROM EXERCISE OF THIS LICENSE AGREEMENT OR THE USE OF
    THE SOFTWARE.
*/
package org.globus.ogsa.impl.base.multirft;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import java.net.URL;
import java.net.MalformedURLException;

import java.rmi.RemoteException;

import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import javax.xml.namespace.QName;

import org.apache.axis.MessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.gridforum.ogsi.ServiceDataType;
//import org.gridforum.ogsi.ServiceLocatorType;

import org.globus.ogsa.base.multirft.FileTransferProgressType;
import org.globus.ogsa.base.multirft.FileTransferRestartMarker;
import org.globus.ogsa.base.multirft.FileTransferStatusElement;
import org.globus.ogsa.base.multirft.FileTransferJobStatusType;
import org.globus.ogsa.base.multirft.GridFTPRestartMarkerElement;
import org.globus.ogsa.base.multirft.GridFTPRestartMarkerType;
import org.globus.ogsa.base.multirft.GridFTPPerfMarkerElement;
import org.globus.ogsa.base.multirft.GridFTPPerfMarkerType;
import org.globus.ogsa.base.multirft.RFTPortType;
import org.globus.ogsa.base.multirft.TransferType;
import org.globus.ogsa.base.multirft.TransferStatusType;
import org.globus.ogsa.base.multirft.TransferRequestType;
import org.globus.ogsa.base.multirft.FileTransferJobStatusType;
import org.globus.ogsa.base.multirft.RFTOptionsType;
import org.globus.ogsa.base.multirft.Version;
import org.globus.ogsa.base.multirft.TransferRequestElement;

import org.globus.ogsa.impl.base.multirft.TransferDbOptions;
import org.globus.ogsa.impl.base.multirft.TransferJob;
import org.globus.ogsa.impl.base.multirft.TransferDbAdapter;

import javax.security.auth.Subject;
import org.globus.gsi.jaas.JaasGssUtil;
import org.globus.ogsa.config.ConfigException;
import org.globus.ogsa.config.ContainerConfig;
import org.globus.ogsa.GridConstants;
import org.globus.ogsa.GridContext;
import org.globus.ogsa.GridServiceException;

import org.globus.ogsa.impl.core.handle.HandleHelper;
import org.globus.ogsa.impl.ogsi.GridServiceImpl;

import org.globus.ogsa.ServiceProperties;
import org.globus.ogsa.ServiceData;
import org.globus.ogsa.impl.security.authentication.SecContext;
import org.globus.ogsa.utils.MessageUtils;
import org.globus.ogsa.utils.AnyHelper;
import org.globus.ogsa.wsdl.GSR;
 
import org.globus.ogsa.impl.security.SecurityManager;
import org.globus.axis.gsi.GSIConstants;
import org.globus.gsi.gssapi.auth.SelfAuthorization;
import org.globus.util.Util;

import org.globus.util.GlobusURL;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.ietf.jgss.GSSCredential;
import org.globus.ogsa.impl.security.authentication.SecureServicePropertiesHelper;
public class RftImpl
    extends GridServiceImpl {
    static Log logger = LogFactory.getLog (RftImpl.class.getName ());
    String configPath;
    TransferRequestType transferRequest;
    TransferRequestElement transferRequestElement;
    TransferType transfers[];
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

    public RftImpl() {
        super("MultifileRFTService");
        this.transferRequest = null;
    }

    public RftImpl(TransferRequestType transferRequest) {
        super ("MultifileRFTService");
        String name="MultifileRFTService";
      //  String id = String.valueOf( hashCode() );
        

      //  setProperty( ServiceProperties.NAME, name);
        this.transferRequest = transferRequest;
        if(transferRequest == null ) {
            System.out.println("transfer request is null");
        }
    /*    transferProgress = new FileTransferProgressType();
        restartMarkerDataType = new FileTransferRestartMarker();*/
    }
   
    public int start() 
        throws RemoteException {
        Subject subject;
        MessageContext ctx = MessageContext.getCurrentContext ();
        SecContext secContext = (SecContext) ctx.getProperty(
                                                org.globus.ogsa.impl.security.authentication.Constants.CONTEXT);
        if (secContext == null) {
            throw new RemoteException ("Service must be accessed Securely");
        }
        subject = SecurityManager.getManager().setServiceOwnerFromContext(this);
        
        GSSCredential cred = JaasGssUtil.getCredential(subject);
        if (cred == null) {
            throw new RemoteException("Delegation not performed");
        }
        try {
            String path = TransferClient.saveCredential(cred);
            Util.setFilePermissions (path,600);
            logger.debug ("Credential saved at : " + path);
            logger.debug ("Got a credential with Subject: " + 
                          cred.getName().toString());
            dbAdapter.storeProxyLocation(requestId,path);
        
       //     this.transferRequest = transferRequestElement.getTransferRequest();
            int temp = 0;
            while( temp < concurrency ) {
                TransferJob transferJob = new TransferJob(transfers[temp],TransferJob.STATUS_PENDING,0);
                TransferThread transferThread = new TransferThread(transferJob);
                transferThread.start();
                activeTransferThreads.add(transferThread);
                temp = temp + 1;
            }
        } catch (Exception e) {
            logger.error("Error in start " + e.toString(),e);
            throw new RemoteException(MessageUtils.toString(e));
        }
        
        
        return requestId;
  }      

    public void cancel(int requestId,int fromId,int toId)
        throws RemoteException {
       logger.debug("Cancelling transfers of the request: "+ requestId);
       logger.debug("from id: " + fromId + "to id: " + toId);
       dbAdapter.cancelTransfers(requestId,fromId,toId);
       cancelActiveTransfers(fromId,toId);
    }
    
    public void cancelActiveTransfers(int fromId, int toId) 
    throws RftDBException {
        for (int i=fromId;i<=toId; i++) {
                TransferThread tempTransferThread = 
                    (TransferThread)activeTransferThreads.elementAt(i);
                tempTransferThread.killThread();
            }
            
    }
    private void notifyUpdate() {
        logger.debug("Notifying Update");
    }
    public void postCreate(GridContext messageContext)
        throws GridServiceException {
        try {
            super.postCreate (messageContext);
            logger.debug("In postCreate");
            
            ServiceProperties factoryProperties = (ServiceProperties)
                                    getProperty (ServiceProperties.FACTORY);
            
            transferProgress = new FileTransferProgressType();
            restartMarkerDataType = new FileTransferRestartMarker();
            fileTransferStatusElement = new FileTransferStatusElement();
            gridFTPRestartMarkerSDE = new GridFTPRestartMarkerElement();
            gridFTPPerfMarkerSDE = new GridFTPPerfMarkerElement();
            version = new Version();

            this.requestStatusData = 
                this.serviceData.create("FileTransferStatus");
            this.transferProgressData = 
                this.serviceData.create("FileTransferProgress");
            this.singleFileTransferStatusSDE = 
                this.serviceData.create("SingleFileTransferStatus");
            this.restartMarkerServiceData = 
                this.serviceData.create("FileTransferRestartMarker");
            this.gridFTPRestartMarkerSD = 
                this.serviceData.create("GridFTPRestartMarker");
            this.gridFTPPerfMarkerSD =
                this.serviceData.create("GridFTPPerfMarker");
            this.versionSD =
                this.serviceData.create("MultiRFTVersion");

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
            
            FileTransferJobStatusType statusType= new FileTransferJobStatusType();
            statusType.setTransferId(-1);
            statusType.setDestinationUrl("destURLPlaceHolder");
            statusType.setStatus(null);
            fileTransferStatusElement.setRequestStatus(statusType);
            this.singleFileTransferStatusSDE.setValue(fileTransferStatusElement);
            this.serviceData.add(singleFileTransferStatusSDE);
            
            gridFTPRestartMarkerSDE.setGridFTPRestartMarker(new GridFTPRestartMarkerType());
            this.gridFTPRestartMarkerSD.setValue(this.gridFTPRestartMarkerSDE);
            this.serviceData.add(this.gridFTPRestartMarkerSD);

           gridFTPPerfMarkerSDE.setGridFTPPerfMarker(new GridFTPPerfMarkerType());
           this.gridFTPPerfMarkerSD.setValue(this.gridFTPPerfMarkerSDE);
           this.serviceData.add(this.gridFTPPerfMarkerSD);
            
            
          //  requestStatusData.setValues(new Object[] {fileTransferStatusElement1,
         //                   fileTransferStatusElement2});
          //  this.serviceData.add(requestStatusData);
            
            String persistentRequestIdString = (String)getPersistentProperty("requestId");
            
            String temp = (String)factoryProperties.getProperty (
                              "maxAttempts");
            int maxAttempts = Integer.parseInt (temp);
            String jdbcDriver = (String)factoryProperties.getProperty (
                             "JdbcDriver");
            String connectionURL = (String)factoryProperties.getProperty (
                                "connectionURL");
            String userName = (String)factoryProperties.getProperty ("dbusername");
            String password = (String)factoryProperties.getProperty ("password");
        
            dbOptions = new TransferDbOptions(jdbcDriver,
                                          connectionURL,
                                          userName,
                                          password);
            dbAdapter = TransferDbAdapter.setupDBConnection(dbOptions);
            
            activeTransferThreads = new Vector();
            
            if(persistentRequestIdString != null) {
                logger.debug("recovering transfer request: " + persistentRequestIdString);
                this.persistentRequestId = Integer.parseInt(persistentRequestIdString);
                this.requestId = this.persistentRequestId;
                String proxyLocation = dbAdapter.getProxyLocation (this.persistentRequestId);
                
                GSSCredential credential = TransferClient.loadCredential(proxyLocation);
                setNotifyProps(credential,
                    org.globus.ogsa.impl.security.authentication.Constants.ENCRYPTION);

                
                Vector recoveredTransferJobs = dbAdapter.getActiveTransfers(persistentRequestId);
                int tempSize = recoveredTransferJobs.size();
                transfers = new TransferType[tempSize];
                for(int i=0;i<tempSize;i++) {
                    TransferJob transferJob = (TransferJob)recoveredTransferJobs.elementAt(i);
                    //converting recovered transfers to transfer types 
                    transfers[i] = new TransferType();
                    transfers[i].setTransferId(transferJob.getTransferId());
                    transfers[i].setSourceUrl(transferJob.getSourceUrl());
                    transfers[i].setDestinationUrl(transferJob.getDestinationUrl());
                    transfers[i].setRftOptions(transferJob.getRftOptions());
                }

                int concurrency_ = dbAdapter.getConcurrency(this.persistentRequestId);
                logger.debug("Concurrency of recovered request: " + concurrency_);
                logger.debug("Populating FileTransferStatus SDEs");
                fileTransferStatusElements = new FileTransferStatusElement[transfers.length];
                statusTypes = new FileTransferJobStatusType[transfers.length];
               // transferJobId_ = dbAdapter.getTransferJobId(requestId);
                
                for(int i=0;i<transfers.length;i++) {
                    statusTypes[i] = new FileTransferJobStatusType();
                    statusTypes[i].setTransferId(transfers[i].getTransferId());
                    statusTypes[i].setDestinationUrl(transfers[i].getDestinationUrl());
                    statusTypes[i].setStatus(mapStatus(TransferJob.STATUS_PENDING));
                    fileTransferStatusElements[i] = new FileTransferStatusElement();
                    fileTransferStatusElements[i].setRequestStatus(statusTypes[i]);
                }
                
                requestStatusData.setValues(new Object[] {fileTransferStatusElements});
                this.serviceData.add(requestStatusData);
                
                for(int i =0;i<concurrency_;i++) {
                    TransferJob transferJob = (TransferJob)recoveredTransferJobs.elementAt(i);
                    int tempStatus = transferJob.getStatus();
                    if((tempStatus == TransferJob.STATUS_ACTIVE) ||
                        (tempStatus == TransferJob.STATUS_PENDING)) {
                        TransferThread transferThread = new TransferThread(transferJob);
                        logger.debug("Starting recovered transfer jobs ");
                        transferThread.start();
                    }
                }
            } else {
               // CredentialProvider provider = (CredentialProvider) getProperty(ServiceProperties.CREDENTIAL_PROVIDER);
                
                /*GSSCredential credential = provider.transferCredential (messageContext);
                setNotifyProps(credential,
                messageContext.getMessageContext().getProperty (org.globus.ogsa.impl.security.authentication.Constants.MSG_SEC_TYPE));*/
                SecurityManager manager = SecurityManager.getManager();
                //GSSCredential cred = manager.setServiceOwnerFromContext(this, messageContext);
		 GSSCredential cred = SecureServicePropertiesHelper.getCredential(this);
                transfers = this.transferRequest.getTransferArray();
                this.concurrency = transferRequest.getConcurrency();
                requestId = dbAdapter.storeTransferRequest(this.transferRequest);
                
                setPersistentProperty("requestId",
                                 Integer.toString( requestId));
                setPersistentProperty("activateOnStartup", Boolean.TRUE.toString());
                flush();
                this.persistentRequestId = requestId;
                
                logger.debug("Populating FileTransferStatus SDEs");
                
                fileTransferStatusElements = new FileTransferStatusElement[transfers.length];
                statusTypes = new FileTransferJobStatusType[transfers.length];
                transferJobId_ = dbAdapter.getTransferJobId(requestId);
                logger.debug("setting transferid in statusTypes to : " + transferJobId_);
                
                for(int i=0;i<transfers.length;i++) {
                    statusTypes[i] = new FileTransferJobStatusType();
                    statusTypes[i].setTransferId(transferJobId_++);
                    statusTypes[i].setDestinationUrl(transfers[i].getDestinationUrl());
                    statusTypes[i].setStatus(mapStatus(TransferJob.STATUS_PENDING));
                    fileTransferStatusElements[i] = new FileTransferStatusElement();
                    fileTransferStatusElements[i].setRequestStatus(statusTypes[i]);
                }
                
                requestStatusData.setValues(new Object[] {fileTransferStatusElements});
                this.serviceData.add(requestStatusData);

            }
            } catch (Exception e) {
                throw new GridServiceException(e);
            }
    }
    private TransferStatusType mapStatus(int transferStatus) {
        if ( transferStatus == 0) {
            return TransferStatusType.Finished;
        }
        if ( transferStatus == 1) {
            return TransferStatusType.Retrying;
        }
        if ( transferStatus == 2) {
            return TransferStatusType.Failed;
        }
        if ( transferStatus == 3) {
            return TransferStatusType.Active;
        }
        if ( transferStatus == 4) {
            return TransferStatusType.Pending;
        }
        if ( transferStatus == 5) {
            return TransferStatusType.Cancelled;
        }
        return null;
    }
    
    private void setNotifyProps(GSSCredential credential,
                                Object msgProt) {
        this.notifyProps = new HashMap();
        this.notifyProps.put (GSIConstants.GSI_MODE,
                              GSIConstants.GSI_MODE_NO_DELEG);
        //this.notifyProps.put (org.globus.ogsa.impl.security.authentication.Constants.ESTABLISH_CONTEXT, Boolean.TRUE);
        this.notifyProps.put (org.globus.ogsa.impl.security.authentication.Constants.MSG_SEC_TYPE,
                              msgProt);
        this.notifyProps.put (GSIConstants.GSI_AUTHORIZATION,
                                SelfAuthorization.getInstance());
        this.notifyProps.put (GSIConstants.GSI_CREDENTIALS,
                              credential);
    }

    public void preDestroy()
        throws Exception {
        logger.debug ("RFT instance destroyed");
    }
    public void statusChanged( TransferJob transferJob) 
    throws GridServiceException {
            logger.debug("Single File Transfer Status SDE changed " );
            dbAdapter.update(transferJob);
            transferJobId_ = transferJob.getTransferId();
            FileTransferJobStatusType statusType= new FileTransferJobStatusType();
            statusType.setTransferId(transferJob.getTransferId());
            statusType.setDestinationUrl(transferJob.getDestinationUrl());
            statusType.setStatus(mapStatus(transferJob.getStatus()));
            this.fileTransferStatusElement.setRequestStatus(statusType);
            this.singleFileTransferStatusSDE.setValue(fileTransferStatusElement);
            this.serviceData.add(singleFileTransferStatusSDE);
            singleFileTransferStatusSDE.notifyChange();
            for(int i=0;i<transfers.length;i++) {
                if ( statusTypes[i].getTransferId() == transferJob.getTransferId() ) {
                    statusTypes[i].setStatus(mapStatus(transferJob.getStatus()));
                }
            }
        
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
            this.attempts = transferJob.getAttempts ();
            this.status = transferJob.getStatus ();
        }

        public void killThread() throws RftDBException {
            transferJob.setStatus(TransferJob.STATUS_CANCELLED);
            dbAdapter.update(transferJob);
        }

        public void run() {
            try {
                int tempId = transferJob.getTransferId ();
                TransferThread transferThread;
                RFTOptionsType rftOptions = transferJob.getRftOptions();
                String proxyLocation = dbAdapter.getProxyLocation (
                                               requestId);
                logger.debug("Proxy location" + proxyLocation+ " "+ requestId);
                try {
                    logger.debug("in run");
                    transferClient = new TransferClient(tempId,
                                                    transferJob.getSourceUrl (),
                                                    transferJob.getDestinationUrl (),
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
                    } catch (Exception e) {
                        logger.error("Error in Transfer Client" + e.toString(),e);
    			        transferJob.setStatus(TransferJob.STATUS_FAILED);
                        statusChanged(transferJob);
	    		        notifyUpdate();
                        TransferJob newTransferJob = dbAdapter.getTransferJob(requestId);
                        
                        if (newTransferJob != null ) {
                            transferThread = new TransferThread(newTransferJob);
                            logger.debug("Attempts in new transfer: " + newTransferJob.getAttempts());
                            transferThread.start();
                            newTransferJob.setStatus(TransferJob.STATUS_ACTIVE);
                            notifyUpdate ();
                            statusChanged(newTransferJob);
                    }
                    else {
                        logger.debug("No more transfers " );
                    }
                    throw new RemoteException(MessageUtils.toString(e));
                }
                    
                    
                String restartMarker = dbAdapter.getRestartMarker (
                                               tempId);
                if(restartMarker != null) {
                    transferClient.setRestartMarker (restartMarker);
                    //ADD STUFF HERE
                }
                if (transferClient != null) {
                    
                    transferClient.setParallelStreams (rftOptions.getParallelStreams ());
                    transferClient.setTcpBufferSize (rftOptions.getTcpBufferSize ());
                    transferClient.setRFTOptions(rftOptions);
                    transferClient.transfer ();
                    transferJob.setStatus(TransferJob.STATUS_ACTIVE);
                    dbAdapter.update (transferJob);
                    transferJob.setStatus (transferClient.getStatus ());
                    statusChanged(transferJob);
                    int x = transferClient.getStatus ();
                    transferJob.setAttempts (transferJob.getAttempts () + 1);
                    if(x == 0) {
                        transferJob.setStatus (TransferJob.STATUS_FINISHED);
                        notifyUpdate ();
                        statusChanged(transferJob);
                        transferProgress.setPercentComplete(100);
                        transferProgressData.setValue(transferProgress);
                    }
                    else if((x == 1) && 
                             (transferJob.getAttempts () < maxAttempts)) {
                        transferJob.setStatus (TransferJob.STATUS_PENDING);
                        notifyUpdate();
                        statusChanged(transferJob);
                 /*     transferThread = new TransferThread(transferJob);
                        transferThread.start();
                        transferJob.setStatus(TransferJob.STATUS_ACTIVE);
                        notifyUpdate(); */
                    }
                    else if((x == 2) || 
                             (transferJob.getAttempts () >= maxAttempts)) {
                        transferJob.setStatus (TransferJob.STATUS_FAILED);
                        statusChanged(transferJob);
                    }
                    else {
                        transferJob.setStatus (TransferJob.STATUS_RETRYING);
                   /*   transferThread = new TransferThread(transferJob);
                        transferThread.start();
                        transferJob.setStatus(TransferJob.STATUS_ACTIVE);*/
                        notifyUpdate();
                        statusChanged(transferJob);
                    }
                } else {
                    transferJob.setStatus(TransferJob.STATUS_FAILED);
                    statusChanged(transferJob);
                }
                    dbAdapter.update (transferJob);
                    TransferJob newTransferJob =dbAdapter.getTransferJob(requestId);
                    logger.debug("starting a new transfer");
                    if (newTransferJob != null ) {
                        transferThread = new TransferThread(newTransferJob);
                        logger.debug("Attempts in new transfer: " + newTransferJob.getAttempts());
                        transferThread.start();
                        newTransferJob.setStatus(TransferJob.STATUS_ACTIVE);
                        notifyUpdate ();
                        statusChanged(newTransferJob);
                    }
                    else {
                        logger.debug("No more transfers " );
                    }
                }
             catch(Exception ioe) {
                logger.error ("Error in Transfer Thread" + ioe.toString (),
                              ioe);
            }
             catch(Throwable ee) {
                logger.error ("Error in Transfer Thread" + ee.toString (),
                              ee);
            }
        }
    }

}
