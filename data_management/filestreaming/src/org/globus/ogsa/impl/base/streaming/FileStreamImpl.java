/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
package org.globus.ogsa.impl.base.streaming;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.rmi.RemoteException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;

import javax.xml.namespace.QName;
import javax.security.auth.Subject;

import org.apache.axis.MessageContext;
import org.apache.axis.types.URI;
import org.apache.axis.types.URI.MalformedURIException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.Logger;

import org.globus.axis.gsi.GSIConstants;
import org.globus.ftp.exception.FTPException;
import org.globus.gsi.jaas.JaasGssUtil;
import org.globus.io.gass.client.GassException;
import org.globus.io.streams.FTPOutputStream;
import org.globus.io.streams.GassOutputStream;
import org.globus.io.streams.GlobusFileOutputStream;
import org.globus.io.streams.GridFTPOutputStream;
import org.globus.io.streams.HTTPOutputStream;
import org.globus.ogsa.ServiceProperties;
import org.globus.ogsa.ServiceData;
import org.globus.ogsa.base.streaming.CredentialsFault;
import org.globus.ogsa.base.streaming.FileStreamOptionsType;
import org.globus.ogsa.base.streaming.FileStreamOptionsWrapperType;
import org.globus.ogsa.base.streaming.FileStreamPortType;
import org.globus.ogsa.base.streaming.FileTransferFault;
import org.globus.ogsa.base.streaming.InvalidPathFault;
import org.globus.ogsa.base.streaming.InvalidUrlFault;
import org.globus.ogsa.GridConstants;
import org.globus.ogsa.GridContext;
import org.globus.ogsa.GridServiceException;
import org.globus.ogsa.impl.ogsi.GridServiceImpl;
import org.globus.ogsa.impl.security.authentication.SecureServicePropertiesHelper;
import org.globus.ogsa.impl.security.SecurityManager;
import org.globus.ogsa.impl.security.authentication.Constants;
import org.globus.ogsa.repository.ServiceNode;
import org.globus.ogsa.utils.AnyHelper;
import org.globus.ogsa.utils.FaultHelper;
import org.globus.ogsa.utils.MessageUtils;
import org.globus.ogsa.utils.QueryHelper;
import org.globus.util.GlobusURL;
import org.globus.util.Tail;

import org.gridforum.ogsi.ExtensibilityType;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

public class FileStreamImpl extends GridServiceImpl {
    
    static Log logger = LogFactory.getLog (FileStreamImpl.class.getName());

    private static final String FSS_NAMESPACE =
        "http://www.globus.org/namespaces/2003/04/base/streaming";
    private static final QName DEST_URL_SDE_QNAME =
        new QName(FSS_NAMESPACE, "destinationUrl");
    private static final QName DONE_SDE_QNAME =
        new QName(FSS_NAMESPACE, "done");
    private static final String FILE_STREAMING_RESOURCES =
            "org.globus.ogsa.impl.base.streaming.Resources";
    protected Tail outputFollower;
    protected boolean appendStdout = true;
    protected GSSCredential proxy = null;
    private String sourcePath;
    private String destinationUrl;
    private int offset;
    private OutputStream outputStream;
    private Vector fileStreamStateListeners = new Vector();
    private ServiceData doneServiceData;
    private boolean isStopped = false;

    public FileStreamImpl() {
        super("FileStreamImpl");

        String name = "FileStream";
        String id = String.valueOf(hashCode());
        if(id != null) {
            name = name + "(" + id + ")";
        }
        setProperty (ServiceProperties.NAME, name);
    }

    private void addDestinationUrlServiceData() throws GridServiceException {
        ServiceData destinationUrlServiceData =
            this.serviceData.create(DEST_URL_SDE_QNAME);
        destinationUrlServiceData.setValue(this.destinationUrl);
        this.serviceData.add(destinationUrlServiceData);
    }

    private void addDoneServiceData() throws GridServiceException {
        logger.debug("Setting \"done\" to FALSE\"");
        doneServiceData = this.serviceData.create(DONE_SDE_QNAME);
        doneServiceData.setValue(Boolean.FALSE);
        this.serviceData.add(doneServiceData);
    }
    
    public void postCreate(GridContext context) throws GridServiceException {
        super.postCreate(context);
        SecurityManager manager = SecurityManager.getManager();
        manager.setServiceOwnerFromContext(this, context);

        //get factory's source path
        FileStreamFactoryImpl factory
            = (FileStreamFactoryImpl) getProperty(ServiceProperties.FACTORY);
        ServiceData factoryServiceData = factory.getServiceDataSet().get(
                FileStreamFactoryImpl.SOURCE_PATH_SD_QNAME);
        this.sourcePath = (String) factoryServiceData.getValue();

        if (logger.isDebugEnabled()) {
            logger.debug("source path: " + this.sourcePath);
        }

        //Get creation options
        ExtensibilityType creationExtensibility
            = (ExtensibilityType) getProperty(
                    ServiceProperties.CREATION_EXTENSIBILITY);

        FileStreamOptionsWrapperType fileStreamOptionsWrapper = null;
        try {
            fileStreamOptionsWrapper
                = (FileStreamOptionsWrapperType) AnyHelper.getAsSingleObject(
                        creationExtensibility,
                        FileStreamOptionsWrapperType.class);
        } catch (ClassCastException cce) {
            throw new GridServiceException(
                "invalid service creation parameters type", cce);
        }
        FileStreamOptionsType fileStreamOptions
            = fileStreamOptionsWrapper.getFileStreamOptions();
        this.destinationUrl = fileStreamOptions.getDestinationUrl();
        this.offset = fileStreamOptions.getOffset();

        if (logger.isDebugEnabled()) {
            logger.debug("destination URL: " + this.destinationUrl);
            logger.debug("offset: " + this.offset);
        }

        addDestinationUrlServiceData();
        addDoneServiceData();
    }
    
    protected OutputStream openUrl(String file) throws InvalidUrlFault,
            FileTransferFault, CredentialsFault, InvalidPathFault {
        GlobusURL url = null;
        try {
            url = new GlobusURL(file);
        } catch(MalformedURLException e) {
            String message = MessageUtils.getMessage(
                    FILE_STREAMING_RESOURCES,
                    "InvalidUrlFault00",
                    new String [] { file });
            InvalidUrlFault fault = (InvalidUrlFault) FaultHelper.makeFault(
                    InvalidUrlFault.class, message, e, this);

            throw fault;
        }
        return openUrl(url);
    }

    protected OutputStream openUrl(GlobusURL url) throws InvalidPathFault,
            InvalidUrlFault, FileTransferFault, CredentialsFault {
        String protocol = url.getProtocol();
        String message;

        try {
            if (protocol.equalsIgnoreCase("https")) {
                return new GassOutputStream(this.proxy,
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
                return new GridFTPOutputStream(this.proxy, 
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
                message = MessageUtils.getMessage(
                        FILE_STREAMING_RESOURCES,
                        "InvalidUrlFault01",
                        new String [] { protocol });
                InvalidUrlFault f =
                        (InvalidUrlFault) FaultHelper.makeFault(
                        InvalidUrlFault.class,
                        message, null, this);

                f.setUrl(url.getURL());

                throw f;
            }
        } catch(FTPException fe) {
            message = MessageUtils.getMessage(
                    FILE_STREAMING_RESOURCES,
                    "FileTransferFault00",
                    new String [] { url.getURL() });
            FileTransferFault f =
                    (FileTransferFault) FaultHelper.makeFault(
                    FileTransferFault.class,
                    message, fe, this);
            f.setSourcePath(sourcePath);
            try {
                f.setDestinationUrl(new URI(url.getURL()));
            } catch(MalformedURIException muri) {
                message = MessageUtils.getMessage(
                        FILE_STREAMING_RESOURCES,
                        "InvalidUrlFault00",
                        new String [] { url.getURL() });
                InvalidUrlFault fault =
                        (InvalidUrlFault) FaultHelper.makeFault(
                        InvalidUrlFault.class,
                        message, muri, this);

                fault.setUrl(url.getURL());

                throw fault;
            }

            throw f;
        } catch(GassException ge) {
            message = MessageUtils.getMessage(
                    FILE_STREAMING_RESOURCES,
                    "FileTransferFault00",
                    new String [] { url.getURL() });
            FileTransferFault f =
                    (FileTransferFault) FaultHelper.makeFault(
                    FileTransferFault.class,
                    message, ge, this);
            f.setSourcePath(sourcePath);
            try {
                f.setDestinationUrl(new URI(url.getURL()));
            } catch(MalformedURIException muri) {
                message = MessageUtils.getMessage(
                        FILE_STREAMING_RESOURCES,
                        "InvalidUrlFault00",
                        new String [] { url.getURL() });
                InvalidUrlFault fault =
                        (InvalidUrlFault) FaultHelper.makeFault(
                        InvalidUrlFault.class,
                        message, null, this);

                fault.setUrl(url.getURL());

                throw fault;
            }

            throw f;
        } catch(GSSException gse) {
            message = MessageUtils.getMessage(
                    FILE_STREAMING_RESOURCES,
                    "CredentialsFault00",
                    new String [] { url.getURL() });
            CredentialsFault f =
                    (CredentialsFault) FaultHelper.makeFault(
                    CredentialsFault.class,
                    message, gse, this);
            f.setSourcePath(sourcePath);
            try {
                f.setDestinationUrl(new URI(url.getURL()));
            } catch(MalformedURIException muri) {
                message = MessageUtils.getMessage(
                        FILE_STREAMING_RESOURCES,
                        "InvalidUrlFault00",
                        new String [] { url.getURL() });
                InvalidUrlFault fault =
                        (InvalidUrlFault) FaultHelper.makeFault(
                        InvalidUrlFault.class,
                        message, null, this);

                fault.setUrl(url.getURL());

                throw fault;
            }
            throw f;
        } catch(IOException ioe) {
            if (protocol.equalsIgnoreCase("file")) {
                message = MessageUtils.getMessage(
                        FILE_STREAMING_RESOURCES,
                        "InvalidPathFault00",
                        new String [] { url.getPath() });
                InvalidPathFault fault = (InvalidPathFault)
                        FaultHelper.makeFault(
                        InvalidPathFault.class,
                        message, ioe, this);
                fault.setPath(url.getPath());
                throw fault;
            } else {
                message = MessageUtils.getMessage(
                        FILE_STREAMING_RESOURCES,
                        "FileTransferFault00",
                        new String [] { url.getURL() });
                FileTransferFault f =
                        (FileTransferFault) FaultHelper.makeFault(
                        FileTransferFault.class,
                        message, ioe, this);
                f.setSourcePath(sourcePath);
                try {
                    f.setDestinationUrl(new URI(url.getURL()));
                } catch(MalformedURIException muri) {
                    message = MessageUtils.getMessage(
                            FILE_STREAMING_RESOURCES,
                            "InvalidUrlFault00",
                            new String [] { url.getURL() });
                    InvalidUrlFault fault =
                            (InvalidUrlFault) FaultHelper.makeFault(
                            InvalidUrlFault.class,
                            message, null, this);

                    fault.setUrl(url.getURL());

                    throw fault;
                }
                throw f;
            }
        }
    }

    public void preDestroy(GridContext context) 
    throws GridServiceException {
        if(!isStopped) {
            try {
                outputStream.close();
                if (logger.isDebugEnabled()) {
                    logger.debug("File Stream instance is destroyed");
                }
            }catch(java.io.IOException ioe) {
                logger.error("Error in destroying the File Stream Instance",ioe);
            }
        } else {
            logger.debug("FileStream already closed");
        }
        super.preDestroy(context);
    }

    public void addFileStreamStateListener(
            FileStreamStateListener                 listener) {
        this.fileStreamStateListeners.add(listener);
    }

    public void removeFileStreamStateListener(
            FileStreamStateListener                 listener) {
        this.fileStreamStateListeners.remove(listener);
    }

    public void fireFileStreamStarted() {
        Iterator listenerIter = this.fileStreamStateListeners.iterator();
        while (listenerIter.hasNext()) {
            FileStreamStateListener listener
                = (FileStreamStateListener) listenerIter.next();
            listener.fileStreamStarted();
        }
    }

    public void fireFileStreamStopped() {
        Iterator listenerIter = this.fileStreamStateListeners.iterator();
        while (listenerIter.hasNext()) {
            FileStreamStateListener listener
                = (FileStreamStateListener) listenerIter.next();
            listener.fileStreamStopped();
        }
    }

    public void start() 
	throws InvalidUrlFault, 
	       InvalidPathFault,
	       FileTransferFault, 
	       CredentialsFault,
	       RemoteException {
	logger.debug("starting stream");

	Subject subject = SecurityManager.getManager().getSubject(this);
	// extract gss credential from subject
	this.proxy = JaasGssUtil.getCredential(subject);

        if(this.outputFollower == null) {
            this.outputFollower = new Tail();
            this.outputFollower.setLogger(
                Logger.getLogger(FileStreamImpl.class.getName()));
            this.outputFollower.start();
        }

        File outputFile = new File(this.sourcePath);
        outputStream = openUrl(destinationUrl);
        try {
            this.outputFollower.addFile(outputFile,outputStream,offset);
        } catch(IOException ioe) {
            String message;

            message = MessageUtils.getMessage(
                    FILE_STREAMING_RESOURCES,
                    new String [] { outputFile.toString() });

            InvalidPathFault fault = (InvalidPathFault) FaultHelper.makeFault(
                    InvalidPathFault.class,
                    message, ioe, this);
            fault.setPath(sourcePath);
            throw fault;
        }

        fireFileStreamStarted();
    }

    public void stop() throws RemoteException {
        if (logger.isDebugEnabled()) {
            logger.debug("stopping stream");
        }
        try {
            addDestinationUrlServiceData();
            this.outputFollower.stop();
            boolean joined = false;

            while (!joined) {
                try {
                    this.outputFollower.join();
                    joined = true;
                    if (outputStream != null) {
                        outputStream.close();
                    }
                } catch (InterruptedException ie) {
                } catch (IOException ioe) {
                }
            }
            
            doneServiceData.setValue(Boolean.TRUE);
            doneServiceData.notifyChange();

            fireFileStreamStopped();
            isStopped = true;
        } catch (GridServiceException gse) {
            logger.error("problem stopping source file tailing", gse);
        }
    }
}
