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
package org.globus.ogsa.impl.base.reliabletransfer;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import java.net.URL;
import java.net.MalformedURLException;

import java.rmi.RemoteException;

import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.axis.MessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.gridforum.ogsa.ServiceDataType;
import org.gridforum.ogsa.ServiceLocatorType;

import org.globus.ogsa.base.reliabletransfer.ReliableTransferAttributes;
import org.globus.ogsa.base.reliabletransfer.FileTransferProgressType;
import org.globus.ogsa.base.reliabletransfer.FileTransferRestartMarker;
import org.globus.ogsa.base.reliabletransfer.ReliableTransferOptions;
import org.globus.ogsa.base.reliabletransfer.ReliableTransferPortType;
import org.globus.ogsa.config.ConfigException;
import org.globus.ogsa.config.ContainerConfig;
import org.globus.ogsa.GridConstants;
import org.globus.ogsa.GridContext;
import org.globus.ogsa.GridServiceException;
import org.globus.ogsa.impl.base.reliabletransfer.TransferClient;
import org.globus.ogsa.impl.base.reliabletransfer.TransferDbAdapter;
import org.globus.ogsa.impl.base.reliabletransfer.TransferDbOptions;
import org.globus.ogsa.impl.base.reliabletransfer.TransferJob;

import org.globus.ogsa.impl.core.handle.HandleHelper;
import org.globus.ogsa.impl.core.notification.NotificationSourceDelegationSkeleton;
import org.globus.ogsa.impl.core.notification.SecureNotificationServiceSkeleton;
import org.globus.ogsa.ServiceProperties;
import org.globus.ogsa.ServiceData;
import org.globus.ogsa.impl.security.authentication.SecContext;
import org.globus.ogsa.utils.MessageUtils;
import org.globus.ogsa.utils.AnyHelper;
import org.globus.ogsa.wsdl.GSR;

import org.globus.axis.gsi.GSIConstants;
import org.globus.gsi.gssapi.auth.SelfAuthorization;
import org.globus.util.Util;
import org.globus.util.GlobusURL;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.ietf.jgss.GSSCredential;

public class ReliableTransferImpl
    extends SecureNotificationServiceSkeleton
    implements ReliableTransferPortType {
    static Log logger = LogFactory.getLog (ReliableTransferImpl.class.getName ());
    private static final String TOPIC_ID = "TransferJobStatusGenerator";
    private static final QName TOPIC = new QName(GridConstants.XSD_NS,
                                                 "anyType");
    ServiceData transferProgressData;
    ServiceData restartMarkerServiceData;
    FileTransferProgressType transferProgress;
    FileTransferRestartMarker restartMarkerDataType;
    int maxThreads = 2;
    int maxAttempts = 0;
    private int persistentTransferID = 0;
    private int _transferJobID = 0;
    TransferDbAdapter dbAdapter;
    TransferDbOptions dbOptions;
    String configPath;
    TransferJob transferJob;
    String jdbcDriver;
    String userName;
    String password;
    String connectionURL;
    private Map notifyProps;

    public ReliableTransferImpl() {
        super ("ReliableTransferService");
        String name = "ReliableTransfer";
        String id = String.valueOf (hashCode ());
        if(id != null) {
            name = name + "(" + id + ")";
        }

        setProperty (ServiceProperties.NAME,
                     name);
        transferProgress = new FileTransferProgressType();
        restartMarkerDataType = new FileTransferRestartMarker();
        try {
            ContainerConfig config = ContainerConfig.getConfig ();
            configPath = config.getConfigPath ();
        }
         catch(ConfigException e) {
            logger.error (e);

            return;
        }

    }

    public int submitTransferJob(String fromURL,
                                 String toURL,
                                 ReliableTransferAttributes attributes)
        throws RemoteException {
        MessageContext ctx = MessageContext.getCurrentContext ();
        SecContext secContext = (SecContext)ctx.getProperty (
                                        org.globus.ogsa.impl.security.authentication.Constants.CONTEXT);
        if(secContext == null) {
            throw new RemoteException("Service must be accessed securely.");
        }

        GSSCredential cred = this.secContextSkeleton.getCredential ();
        if(cred == null) {
            // this should never happen since an instance cannot be created without delegation.
            throw new RemoteException("Delegation not performed.");
        }

        int transferJobID = 0;
        ReliableTransferOptions options = attributes.getReliableTransferOptions ();
        try {
            GlobusURL fromGlobusURL = new GlobusURL(fromURL);
            GlobusURL toGlobusURL = new GlobusURL(toURL);
        } catch(MalformedURLException mue) {
            throw new RemoteException("Invalid URLs");
        }
        transferJob = new TransferJob(-1,
                                      fromURL,
                                      toURL,
                                      4,
                                      0,
                                      options);
        try {
	    
	    String path = TransferClient.saveCredential(cred);
	    Util.setFilePermissions (path, 600);
            logger.debug ("Credential saved at : " + path);
            logger.debug ("Got a credential with Subject: " + 
                          cred.getName().toString());
            transferJobID = dbAdapter.storeTransferJob (transferJob);
            setPersistentProperty ("transferID",
                                   Integer.toString (transferJobID));
            flush ();
            this.persistentTransferID = transferJobID;
            this._transferJobID = transferJobID;
            logger.debug ("ID at server:" + transferJobID);
            dbAdapter.storeProxyLocation (transferJobID,
                                          path);
            transferJob.setTransferJobID (transferJobID);
            TransferThread transferThread = new TransferThread(
                                                        transferJob);
            transferJob.setStatus (TransferJob.STATUS_ACTIVE);
            dbAdapter.update (transferJob);
            transferThread.start();

            notifyUpdate ();
        }
         catch(Exception e) {
            logger.error ("Error in SubmitTransfer" + e.toString (),
                          e);
            throw new RemoteException(MessageUtils.toString (
                                              e));
        }

        return transferJobID;
    }

    public int getStatus()
        throws RemoteException {
        if(persistentTransferID != 0) {
            _transferJobID = persistentTransferID;
        }

        logger.debug ("Getting the Transfer Status of " + _transferJobID);
        int status = dbAdapter.getStatus (_transferJobID);

        return status;
    }

    public void cancelTransfer(int transferJobID)
        throws RemoteException {
        try {
            logger.debug ("Cancelled the job");
        }
         catch(Exception e) {
            logger.error ("Error Cancelling transfer " + e.toString (),
                          e);
        }
    }

    public void postCreate(GridContext messageContext)
        throws GridServiceException {
        try {
        super.postCreate (messageContext);
        ServiceProperties factoryProperties = (ServiceProperties)getProperty (
                                                      ServiceProperties.FACTORY);
        this.transferProgressData = 
            this.serviceData.create("FileTransferProgress");
        int progressInt = 0;
        this.transferProgress.setPercentComplete(progressInt);
        this.transferProgressData.setValue(transferProgress);
        this.serviceData.add(transferProgressData);
        this.restartMarkerServiceData = 
            this.serviceData.create("FileTransferRestartMarker");
        this.restartMarkerDataType.setRestartMarkerRange(progressInt);
        this.restartMarkerServiceData.setValue(restartMarkerDataType);
        this.serviceData.add(restartMarkerServiceData);

        String temp = (String)factoryProperties.getProperty (
                              "maxAttempts");
        maxAttempts = Integer.parseInt (temp);
        jdbcDriver = (String)factoryProperties.getProperty (
                             "JdbcDriver");
        connectionURL = (String)factoryProperties.getProperty (
                                "connectionURL");
        String persistentTransferIDString = (String)getPersistentProperty (
                                                    "transferID");
        userName = (String)factoryProperties.getProperty ("username");
        password = (String)factoryProperties.getProperty ("password");
        dbOptions = new TransferDbOptions(jdbcDriver,
                                          connectionURL,
                                          userName,
                                          password);
            dbAdapter = new TransferDbAdapter(dbOptions);
        
        try {
            this.notificationSkeleton.addTopic ("TransferUpdate",
                                                new QName("http://reliabletransfer.base.ogsa.globus.org/reliable_transfer",
                                                          "TransferJob"));
        }
         catch(Exception e) {
            logger.error ("Error handling topic:" + e.toString ());
            logger.error ("Error in postCreate" + e.toString (),
                          e);
        }

        if(persistentTransferIDString != null) {
            this.persistentTransferID = Integer.parseInt (persistentTransferIDString);
            TransferJob transferJob = dbAdapter.getTransferJob (this.persistentTransferID);
            transferJob.setStatus (TransferJob.STATUS_PENDING);
            String proxyLocation = dbAdapter.getProxyLocation (this.persistentTransferID);

            GSSCredential credential = TransferClient.loadCredential(proxyLocation);
            setNotifyProps (credential,
                            org.globus.ogsa.impl.security.authentication.Constants.ENCRYPTION);

            TransferThread transferThread = new TransferThread(transferJob);
            transferThread.start();
        }
         else {
	     // if not restoring then require credential at create time
	     GSSCredential credential = transferCredential (messageContext);

	     // detect the incoming msg protection and use that for notification
	     setNotifyProps (credential,
			     messageContext.getMessageContext().getProperty (org.globus.ogsa.impl.security.authentication.Constants.MSG_SEC_TYPE));
	 }
	} catch(Exception e) {
	    throw new GridServiceException(e);
	}
    }

    private void setNotifyProps(GSSCredential credential,
                                Object msgProt) {
        this.notifyProps = new HashMap();
        this.notifyProps.put (GSIConstants.GSI_MODE,
                              GSIConstants.GSI_MODE_NO_DELEG);
        this.notifyProps.put (org.globus.ogsa.impl.security.authentication.Constants.MSG_SEC_TYPE,
                              msgProt);
        this.notifyProps.put (GSIConstants.GSI_AUTHORIZATION,
                              SelfAuthorization.getInstance());
        this.notifyProps.put (GSIConstants.GSI_CREDENTIALS,
                              credential);
    }

    private void notifyUpdate() {
        try {
            this.notificationSkeleton.notify ("TransferUpdate",
                                              TransferJob.toElement (
                                                      transferJob.getStatus ()),
                                              this.notifyProps);
            logger.debug ("Notifying update for :" + 
                          transferJob.getTransferJobID ());
        }
         catch(Exception e) {
            logger.error ("Error notifying update" + e.toString (),
                          e);
        }
    }

    public void preDestroy()
        throws Exception {
        logger.debug ("RFT instance destroyed");
    }

    public TransferJob[] getTransfers() {

        return (TransferJob[])dbAdapter.getTransfers ().toArray ();
    }

    public class TransferThread
        extends Thread {
        TransferJob transferJob;
        TransferClient transferClient;
        int status;
        int attempts;
        Process p;
        BufferedReader stdInput;
        BufferedReader stdError;

        TransferThread(TransferJob transferJob) {
            this.transferJob = transferJob;
            this.attempts = transferJob.getAttempts ();
            this.status = transferJob.getStatus ();
        }

        public void killThread() {
            p.destroy ();
        }

        public void run() {
            try {
                int tempId = transferJob.getTransferJobID ();
                TransferThread transferThread;
                String proxyLocation = dbAdapter.getProxyLocation (
                                               tempId);
                try {
                    transferClient = new TransferClient(tempId,
                                                    transferJob.getFromURL (),
                                                    transferJob.getToURL (),
                                                    proxyLocation,
                                                    dbOptions,
                                                    transferProgress,
                                                    serviceData,
                                                    transferProgressData,
                                                    restartMarkerServiceData,
                                                    restartMarkerDataType);
                    } catch (Exception e) {
                        logger.error("Error in Transfer Client" + e.toString(),e);
			transferJob.setStatus(TransferJob.STATUS_FAILED);
			notifyUpdate();
                        throw new RemoteException(MessageUtils.toString(e));
                    }
                    
                    
                String restartMarker = dbAdapter.getRestartMarker (
                                               tempId);
                if(restartMarker != null) {
                    transferClient.setRestartMarker (restartMarker);
                    //ADD STUFF HERE
                }
                if (transferClient != null) {
                    transferClient.setParallelStreams (transferJob.getParallelStreams ());
                    transferClient.setTcpBufferSize (transferJob.getTCPBufferSize ());
                    transferClient.transfer ();
                    transferJob.setStatus (transferClient.getStatus ());
                    int x = transferClient.getStatus ();
                    transferJob.setAttempts (transferJob.getAttempts () + 1);
                    if(x == 0) {
                        transferJob.setStatus (TransferJob.STATUS_FINISHED);
                        notifyUpdate ();
                        transferProgress.setPercentComplete(100);
                        transferProgressData.setValue(transferProgress);
                    }
                    else if((x == 1) && 
                             (transferJob.getAttempts () < maxAttempts)) {
                        transferJob.setStatus (TransferJob.STATUS_PENDING);
                        notifyUpdate();
                        transferThread = new TransferThread(transferJob);
                        transferThread.start();
                        transferJob.setStatus(TransferJob.STATUS_ACTIVE);
                        notifyUpdate();
                    }
                    else if((x == 2) || 
                             (transferJob.getAttempts () >= maxAttempts)) {
                        transferJob.setStatus (TransferJob.STATUS_FAILED);
                    }
                    else {
                        transferJob.setStatus (TransferJob.STATUS_RETRYING);
                        transferThread = new TransferThread(transferJob);
                        transferThread.start();
                        transferJob.setStatus(TransferJob.STATUS_ACTIVE);
                        notifyUpdate();
                    }
                } else {
                    transferJob.setStatus(TransferJob.STATUS_FAILED);
                }
                    dbAdapter.update (transferJob);
                    notifyUpdate ();
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
