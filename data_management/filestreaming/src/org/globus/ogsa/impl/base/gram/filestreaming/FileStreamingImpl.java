package org.globus.ogsa.impl.base.gram.filestreaming;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.rmi.RemoteException;
import java.util.HashMap;
import java.util.Calendar;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.axis.MessageContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.Logger;

import org.globus.axis.gsi.GSIConstants;
import org.globus.gatekeeper.jobmanager.internal.Tail;
import org.globus.gsi.gssapi.auth.SelfAuthorization;
import org.globus.io.streams.FTPOutputStream;
import org.globus.io.streams.GassOutputStream;
import org.globus.io.streams.GlobusFileOutputStream;
import org.globus.io.streams.GridFTPOutputStream;
import org.globus.io.streams.HTTPOutputStream;
import org.globus.ftp.exception.FTPException;
import org.globus.ogsa.base.gram.filestreaming.FileStreamingOptionsType;
import org.globus.ogsa.impl.base.gram.filestreaming.CallBackInterface;
import org.globus.ogsa.base.gram.filestreaming.FileStreamingType;
import org.globus.ogsa.base.gram.filestreaming.FileStreamingPortType;
import org.globus.ogsa.base.gram.filestreaming.DestinationURLElement;
import org.globus.ogsa.GridConstants;
import org.globus.ogsa.GridContext;
import org.globus.ogsa.GridServiceException;
import org.globus.ogsa.impl.core.handle.HandleHelper;
import org.globus.ogsa.impl.core.notification.NotificationSourceDelegationSkeleton;
import org.globus.ogsa.impl.core.notification.SecureNotificationServiceSkeleton;
import org.globus.ogsa.impl.core.handle.HandleHelper;
import org.globus.ogsa.impl.security.authentication.SecContext;
import org.globus.ogsa.ServiceProperties;
import org.globus.ogsa.repository.ServiceNode;
import org.globus.ogsa.utils.MessageUtils;
import org.globus.ogsa.utils.AnyHelper;
import org.globus.ogsa.wsdl.GSR;
import org.globus.ogsa.ServiceData;
import org.gridforum.ogsa.ServiceDataType;
import org.globus.util.GlobusURL;
import org.globus.util.Util;

import org.ietf.jgss.GSSCredential;

public class FileStreamingImpl extends SecureNotificationServiceSkeleton
	implements FileStreamingPortType,CallBackInterface {
	
    static Log logger = LogFactory.getLog (FileStreamingImpl.class.getName());
    private static final String TOPIC_ID = "FileStreamingStatusGenerator";
    private static final QName TOPIC = new QName(GridConstants.XSD_NS,"anyType");
    private static final String DEST_URL_SDE_NAME = "DestinationURL";
    protected Tail _outputFollower;
    protected Logger _jobLogger;
    protected boolean appendStdout = true;
    protected GSSCredential _proxy = null;
    private Map notifyProps;
    private String localPath;
    private String callBack;
    private String destinationURL;
    private int offset;
    private OutputStream out;
    private CallBackInterface managedJobImpl;
    public FileStreamingImpl(FileStreamingType fileStreamingAttributes,
            FileStreamingOptionsType options) {
        super("FileStreamingImpl");
        String name = "FileStreaming";
        String id = String.valueOf (hashCode ());
        if(id != null) {
            name = name + "(" + id + ")";
        }

        setProperty (ServiceProperties.NAME, name);

        initJobLogger();
        this.localPath = fileStreamingAttributes.getPath();
        this.callBack = fileStreamingAttributes.getCallBack();
        this.offset = options.getOffset();
        this.destinationURL = options.getDestinationURL();
    }

    public void callBack() {
        logger.debug("CallBack from Managed Job Impl");
        try {
            addDestinationURLServiceData();
            _outputFollower.stop();
            boolean joined = false;

            while (!joined) {
                try {
                    _outputFollower.join();
                    joined = true;
                } catch (InterruptedException ie) {
                }
            }
            this.managedJobImpl.callBack();
        } catch (GridServiceException gse) {
            logger.error("problem adding service data", gse);
        }
    }

    private void addDestinationURLServiceData() throws GridServiceException {
       // ServiceDataContainer serviceDataContainer = getServiceDataContainer();
        ServiceData destinationURLServiceData =
            this.serviceData.create(DEST_URL_SDE_NAME);
        DestinationURLElement destURLElement = new DestinationURLElement();
        destURLElement.setDestinationURL(this.destinationURL);
        destinationURLServiceData.setValue(destURLElement);
        this.serviceData.add(destinationURLServiceData);
    }
    public void startStreaming() throws RemoteException {
        MessageContext ctx = MessageContext.getCurrentContext ();
        File outputFile = new File(localPath);
        SecContext secContext = (SecContext)ctx.getProperty (
        org.globus.ogsa.impl.security.authentication.Constants.CONTEXT);
        if (secContext == null) {
            throw new RemoteException("Service must be accessed securely.");
        }
        GSSCredential cred = this.secContextSkeleton.getCredential();
        if (cred == null) {
            // this should never happen since an instance cannot be created
            // without delegation.
            throw new RemoteException("Delegation not performed.");
        }
        _proxy = cred;
        out = openUrl(destinationURL);

        if(_outputFollower == null) {
            _outputFollower = new Tail();
            _outputFollower.setLogger(_jobLogger);
            _outputFollower.start();
        }
        try { 
            _outputFollower.addFile(outputFile,out,offset);
        } catch(IOException e) {
            e.printStackTrace();
            throw new RemoteException("Error in Streaming");
        }
    }
    
    public void postCreate(GridContext context) throws GridServiceException {
        super.postCreate(context);
        ServiceProperties factoryProperties = (ServiceProperties)getProperty(
                ServiceProperties.FACTORY);
        GSSCredential credential = transferCredential(context);
        setNotifyProps(credential, context.getProperty (org.globus.ogsa.impl.security.authentication.Constants.MSG_SEC_TYPE));
       
        try {
            logger.debug("CallBack: " + callBack);
            this.managedJobImpl = (CallBackInterface)ServiceNode.getRootNode().activate(callBack);
            this.managedJobImpl.register(this);
        } catch(Exception e) {
            logger.debug("Invalid handle");
            e.printStackTrace();
        }
 
       try {
            startStreaming();
        } catch (RemoteException re) {
            throw new GridServiceException("Error starting streaming", re);
        }
    }
    
    public void register(CallBackInterface callBack) {
    }
    private void setNotifyProps(GSSCredential credential, Object msgProt) {
        this.notifyProps = new HashMap();
        this.notifyProps.put (GSIConstants.GSI_MODE,
                              GSIConstants.GSI_MODE_NO_DELEG);
        this.notifyProps.put(org.globus.ogsa.impl.security.authentication.Constants.ESTABLISH_CONTEXT,Boolean.TRUE);
        this.notifyProps.put(org.globus.ogsa.impl.security.authentication.Constants.MSG_SEC_TYPE,msgProt);
        this.notifyProps.put(GSIConstants.GSI_AUTHORIZATION, SelfAuthorization.getInstance());
        this.notifyProps.put(GSIConstants.GSI_CREDENTIALS,credential);
    }
    
    protected OutputStream openUrl(String file) throws RemoteException {
        GlobusURL url = null;
        try {
            url = new GlobusURL(file);
        } catch(Exception e) {
            throw new RemoteException("Invalid URL");
        }
        try {
            return openUrl(url);
        } catch(Exception e) {
            e.printStackTrace();
            throw new RemoteException("Failed to open remote URL");
        }
    }
    protected void initJobLogger() {
        _jobLogger = Logger.getLogger(FileStreamingImpl.class.getName());

    }
    protected OutputStream openUrl(GlobusURL url) throws Exception {
        String protocol = url.getProtocol();
        if (protocol.equalsIgnoreCase("https")) {
            return new GassOutputStream(_proxy,
                                        url.getHost(),
                                        url.getPort(),
                                        url.getPath(),
                                        -1,
                                        appendStdout);
        } else if (protocol.equalsIgnoreCase("http")) {
            return new HTTPOutputStream(url.getHost(),
                                        url.getPort(),
                                        url.getPath(),
                                        -1,
                                        appendStdout);
        } else if (protocol.equalsIgnoreCase("gsiftp")) {
            return new GridFTPOutputStream(_proxy, 
                                          url.getHost(),
                                          url.getPort(),
                                          url.getPath(),
                                          appendStdout);
        } else if (protocol.equalsIgnoreCase("ftp")) {
            return new FTPOutputStream(url.getHost(),
                                       url.getPort(),
                                       url.getUser(),
                                       url.getPwd(),
                                       url.getPath(),
                                       appendStdout);
        } else if (protocol.equalsIgnoreCase("file")) {
            return new GlobusFileOutputStream(url.getPath(), appendStdout);
        } else {
            throw new Exception("Protocol not supported: " + protocol);
        }
    }
    public void preDestroy() {
        try {
            out.close();
            logger.debug("File Streaming instance is destroyed");
        }catch(java.io.IOException ioe) {
            logger.error("Error in destroying the File Streaming Instance",ioe);
        }
    }
} 
                                                                                                                                    
        
        
