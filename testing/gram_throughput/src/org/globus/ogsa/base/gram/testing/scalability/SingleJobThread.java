package org.globus.ogsa.base.gram.testing.scalability;

import java.io.File;
import java.io.FileReader;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.Calendar;
import java.util.HashMap;

import javax.xml.rpc.Stub;

import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.axis.message.MessageElement;
import org.apache.axis.utils.XMLUtils;
import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.axis.MessageContext;

import org.globus.axis.gsi.GSIConstants;
import org.globus.gsi.proxy.IgnoreProxyPolicyHandler;
import org.globus.ogsa.base.gram.ManagedJobPortType;
import org.globus.ogsa.base.gram.ManagedJobPortType;
import org.globus.ogsa.base.gram.service.ManagedJobServiceGridLocator;
import org.globus.ogsa.base.gram.types.JobStateType;
import org.globus.ogsa.base.gram.types.JobStatusType;
import org.globus.ogsa.handlers.GrimProxyPolicyHandler;
import org.globus.ogsa.impl.base.gram.utils.rsl.JobAttributes;
import org.globus.ogsa.impl.base.gram.utils.rsl.RslParser;
import org.globus.ogsa.impl.base.gram.utils.rsl.RslParserFactory;
import org.globus.ogsa.impl.core.service.ServicePropertiesImpl;
import org.globus.ogsa.NotificationSinkCallback;
import org.globus.ogsa.client.managers.NotificationSinkManager;
import org.globus.ogsa.impl.security.authentication.Constants;
import org.globus.ogsa.impl.security.authorization.HostAuthorization;
import org.globus.ogsa.impl.security.authorization.NoAuthorization;
import org.globus.ogsa.impl.security.authorization.SelfAuthorization;
import org.globus.ogsa.impl.security.SecurityManager;
import org.globus.ogsa.ServiceProperties;
import org.globus.ogsa.utils.AnyHelper;
import org.globus.ogsa.utils.MessageUtils;
import org.globus.ogsa.wsdl.GSR;

import org.gridforum.ogsi.Factory;
import org.gridforum.ogsi.GridService;
import org.gridforum.ogsi.HandleType;
import org.globus.ogsa.utils.GridServiceFactory;
import org.gridforum.ogsi.OGSIServiceGridLocator;
import org.gridforum.ogsi.OGSIServiceLocator;
import org.gridforum.ogsi.LocatorType;
import org.gridforum.ogsi.ExtensibilityType;

import org.w3c.dom.Element;
import java.io.BufferedWriter;
import java.io.FileWriter;

import org.globus.ogsa.tools.ant.StressTest;
import org.globus.ogsa.utils.PerformanceLog;

public class SingleJobThread
    extends                         ServicePropertiesImpl
    implements                      Runnable,
                                    NotificationSinkCallback {

    static Log logger = LogFactory.getLog(SingleJobThread.class.getName());

    ScalabilityTester harness = null;
    String factoryUrl = null;
    Element rsl = null;
    ManagedJobServiceGridLocator mjsLocator = null;
    NotificationSinkManager notificationSinkManager = null;
    String notificationSinkId = null;
    int jobIndex = -1;
    boolean completed = false;

    public SingleJobThread(ScalabilityTester harness, int jobIndex) {
        this.harness = harness;
        this.jobIndex = jobIndex;
        this.factoryUrl = this.harness.getFactoryUrl();

        //retrieve, parse, and validate the RSL
        File file = new File(this.harness.getRslFile());
        RslParser rslParser = RslParserFactory.newRslParser();
        try {
            this.rsl = rslParser.parse(new FileReader(file));
        } catch (Exception e) {
            logger.error("unable to read RSL file", e);
            this.harness.notifyError();
            jobIndex = -1;
        }
    }

    public int getIndex() {
        return this.jobIndex;
    }

    // This method is invoked once each time the stress target is run
    // with this class
    synchronized public void run() {
        if (logger.isDebugEnabled()) {
            logger.debug("running job thread");
        }

        //create service
        try {
            createService();
        } catch (Exception e) {
            logger.error("unable to create MJS instance", e);
            this.harness.notifyError();
            jobIndex = -1;
            return;
        }

        //do actual start call on job
        try {
            startService();
        } catch (Exception e) {
            logger.error("unable to start MJS instance", e);
            this.harness.notifyError();
            jobIndex = -1;
            return;
        }

        cleanup();
    }

    protected void createService() throws Exception {
        if (logger.isDebugEnabled()) {
            logger.debug("creating job");
        }

        //setup factory stub
        OGSIServiceGridLocator factoryLocator = new OGSIServiceGridLocator();
        Factory factory = factoryLocator.getFactoryPort(new URL(factoryUrl));
        ((Stub)factory)._setProperty(Constants.GSI_SEC_MSG,
                                     Constants.SIGNATURE);
        ((Stub)factory)._setProperty(Constants.GRIM_POLICY_HANDLER,
                                 new IgnoreProxyPolicyHandler());
        ((Stub)factory)._setProperty(Constants.AUTHORIZATION,
                                    NoAuthorization.getInstance());
        GridServiceFactory gridServiceFactory
            = new GridServiceFactory(factory);

        //create MJS instance
        if (logger.isDebugEnabled()) {
            logger.debug("creating job");
        }

        ExtensibilityType creationParameters
            = AnyHelper.getExtensibility(this.rsl);
        LocatorType gshHolder
            = gridServiceFactory.createService(creationParameters);
        this.mjsLocator = new ManagedJobServiceGridLocator();
        //This next step caches the GSR in the locator for use later
        ManagedJobPortType managedJob
            = this.mjsLocator.getManagedJobPort(gshHolder);

        try {
            subscribeForNotifications();
        } catch (Exception e) {
            throw new Exception("unable to subscribe for MJS notifications", e);
        }

        this.rsl = null;
    }

    protected void startService() {
        if (logger.isDebugEnabled()) {
            logger.debug("starting job");
        }

        //setup MJS stub
        ManagedJobPortType managedJob = null;
        try {
            managedJob = this.mjsLocator.getManagedJobPort(
                this.mjsLocator.getGSR().getHandle());
        } catch (Exception e) {
            logger.error("unable to get MJS reference", e);
            return;
        }
        ((Stub)managedJob)._setProperty(Constants.GSI_SEC_CONV,
                                        Constants.SIGNATURE);
        ((Stub)managedJob)._setProperty(GSIConstants.GSI_MODE,
                                        GSIConstants.GSI_MODE_FULL_DELEG);
        ((Stub)managedJob)._setProperty(Constants.AUTHORIZATION,
                                        NoAuthorization.getInstance());
        ((Stub)managedJob)._setProperty(Constants.GRIM_POLICY_HANDLER,
                                        new IgnoreProxyPolicyHandler());

        //start job
        JobStatusType jobStatus = null;
        try {
            jobStatus = managedJob.start();
        } catch (Exception e) {
            logger.error("unable to start MJS instance", e);
            this.harness.notifyError();
            jobIndex = -1;
            return;
        }

        //wait for Done or Failed signal
        if (logger.isDebugEnabled()) {
            logger.debug("waiting for signal to stop timming complete");
        }
        while (!completed) {
            try {
                this.wait(15000);
            } catch (Exception e) {
                logger.error("unable to wait", e);
                return;
            }
       }

       this.harness.notifyCompleted(this.jobIndex);

       if (logger.isDebugEnabled()) {
           logger.debug("notified harness that I completed");
       }
    }

    void subscribeForNotifications() throws Exception {
        //create the sink manager and start it listening
        this.notificationSinkManager
            = NotificationSinkManager.getInstance("Secure");
        this.notificationSinkManager.startListening();

        //point the sink manager to the notification source
        this.notificationSinkManager.setService(this.mjsLocator);

        //setup the sink manager security properties
        HashMap notificationSinkProperties = new HashMap();
        notificationSinkProperties.put( Constants.GSI_SEC_CONV,
                                        Constants.SIGNATURE);
        notificationSinkProperties.put( Constants.GRIM_POLICY_HANDLER,
                                        new GrimProxyPolicyHandler());
        notificationSinkProperties.put( Constants.AUTHORIZATION,
                                        SelfAuthorization.getInstance());
        this.notificationSinkManager.init(notificationSinkProperties);

        //add this class as a listener for the notifications
        String mjsNs = org.globus.ogsa.base.gram.StartType.getTypeDesc().
                       getXmlType().getNamespaceURI();
        this.notificationSinkId = this.notificationSinkManager.addListener(
            new QName(mjsNs ,"ManagedJobState"),
            null,
            this.mjsLocator.getGSR().getHandle(),
            this);
    }

    void unsubscribeForNotifications() throws Exception {
        this.notificationSinkManager.removeListener(this.notificationSinkId);
    }

    public void stop() {
        synchronized (this) {
            if (logger.isDebugEnabled()) {
                logger.debug("stopping job thread");
            }
            this.notify();
        }
    }

    public void deliverNotification(ExtensibilityType message) {
        JobStatusType jobStatus = null;
        try {
            jobStatus = (JobStatusType) AnyHelper.getAsSingleObject(
                AnyHelper.getAsServiceDataValues(message),
                JobStatusType.class);
        } catch (Exception e) {
            logger.error("unable to get message as service data", e);
            return;
        }
        JobStateType jobState = jobStatus.getJobState();
        if (logger.isDebugEnabled()) {
            logger.debug("received state notification: " + jobState);
        }

        if (   jobState.equals(JobStateType.Done)
            || jobState.equals(JobStateType.Failed)) {
           synchronized (this) {
                completed = true;
                this.notifyAll();
            }
        }
    }

    protected void cleanup() {
        if (logger.isDebugEnabled()) {
            logger.debug("cleanup() called, cleaning up job thread");
        }
        //unsubscribe for notifications
        try {
            unsubscribeForNotifications();
        } catch (Exception e) {
            logger.error("unable to unsubscribe for MJS notifications", e);
        }

        //destroy MJS instance
        try {
            if (logger.isDebugEnabled()) {
                logger.debug("mjsLocator: " + this.mjsLocator);
                if (this.mjsLocator != null) {
                    GSR gsr = this.mjsLocator.getGSR();
                    logger.debug("gsr: " + gsr);
                    if (gsr != null) {
                        HandleType handle = gsr.getHandle();
                        logger.debug("handle: " + handle);
                    }
                    
                }
            }
            ManagedJobPortType managedJob = this.mjsLocator.getManagedJobPort(
                this.mjsLocator.getGSR().getHandle());
            ((Stub)managedJob)._setProperty(Constants.GSI_SEC_CONV,
                                            Constants.SIGNATURE);
            ((Stub)managedJob)._setProperty(Constants.AUTHORIZATION,
                                            NoAuthorization.getInstance());
            ((Stub)managedJob)._setProperty(Constants.GRIM_POLICY_HANDLER,
                                            new IgnoreProxyPolicyHandler());
            managedJob.destroy();
        } catch (RemoteException re) {
            logger.error("unable to destroy MJS instance", re);
        }
    }
}
