package org.globus.ogsa.base.gram.testing.throughput;

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
import org.globus.gsi.proxy.IgnoreProxyPolicyHandler;

import org.gridforum.ogsi.Factory;
import org.gridforum.ogsi.GridService;
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

    ThroughputTester harness = null;
    String factoryUrl = null;
    String rslFile = null;
    ManagedJobServiceGridLocator mjsLocator = null;
    NotificationSinkManager notificationSinkManager = null;
    String notificationSinkId = null;
    int jobIndex = -1;

    PerformanceLog perfLog = new PerformanceLog(
        SingleJobThread.class.getName());

    public SingleJobThread(ThroughputTester harness, int jobIndex) {
        this.harness = harness;
        this.jobIndex = jobIndex;
        this.factoryUrl = this.harness.getFactoryUrl();
        this.rslFile = this.harness.getRslFile();
    }

    // This method is invoked once each time the stress target is run
    // with this class
    public void run() {
        if (logger.isDebugEnabled()) {
            logger.debug("running job thread");
        }
        //retrieve, parse, and validate the RSL
        File file = new File(rslFile);
        RslParser rslParser = RslParserFactory.newRslParser();
        Element rsl = null;
        try {
            rsl = rslParser.parse(new FileReader(file));
        } catch (Exception e) {
            logger.error("unable to read RSL file", e);
            return;
        }

        //setup factory stub
        OGSIServiceGridLocator factoryLocator = new OGSIServiceGridLocator();
        Factory factory = null;
        try {
            factory = factoryLocator.getFactoryPort(new URL(factoryUrl));
        } catch (Exception e) {
            logger.error("unable to get factory port", e);
            return;
        }
        ((Stub)factory)._setProperty(Constants.GSI_SEC_MSG,
                                     Constants.SIGNATURE);
        ((Stub)factory)._setProperty(Constants.GRIM_POLICY_HANDLER,
                                 new IgnoreProxyPolicyHandler());
        ((Stub)factory)._setProperty(Constants.AUTHORIZATION,
                                    NoAuthorization.getInstance());
        GridServiceFactory gridServiceFactory
            = new GridServiceFactory(factory);

        //start timming createService()
        this.perfLog.start();

        //create MJS instance
        if (logger.isDebugEnabled()) {
            logger.debug("creating job");
        }
        try {
            ExtensibilityType creationParameters
                = AnyHelper.getExtensibility(rsl);
            LocatorType gshHolder
                = gridServiceFactory.createService(creationParameters);
            this.mjsLocator = new ManagedJobServiceGridLocator();
            ManagedJobPortType managedJob
                = mjsLocator.getManagedJobPort(gshHolder);
        } catch (Exception e) {
            logger.error("unable to create MJS instance", e);
            return;
        }

        try {
            subscribeForNotifications();
        } catch (Exception e) {
            logger.error("unable to subscribe for MJS notifications", e);
            return;
        }


        //stop timming createService()
        this.perfLog.stop("createService");
        if (logger.isDebugEnabled()) {
            logger.debug("notifying harness of creation...");
        }
        synchronized (this) {
            this.harness.notifyCreated();
            if (logger.isDebugEnabled()) {
                logger.debug("notifyed harness of creation");
            }

            //wait for start signal
            if (logger.isDebugEnabled()) {
                logger.debug("waiting for signal to start");
            }
            try {
                this.wait();
            } catch (Exception e) {
                logger.error("unable to wait", e);
                return;
            }
        }

        //do actual start call on job
        start0();
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
        String mjsNs = org.globus.ogsa.base.gram.Start.getTypeDesc().
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

    public void start() {
        //non-blocking job start (see run() and start0())
        synchronized (this) {
            this.notifyAll();
        }
    }

    protected void start0() {
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

        //start timming start()
        this.perfLog.start();

        //start job
        try {
            JobStatusType jobState = managedJob.start();
        } catch (Exception e) {
            logger.error("unable to start MJS instance", e);
            return;
        }

        //stop timming start()
        this.perfLog.stop("start");
        if (logger.isDebugEnabled()) {
            logger.debug("notifying harness of start...");
        }
        this.harness.notifyStarted();
        if (logger.isDebugEnabled()) {
            logger.debug("notifyed harness of start");
        }

        //start timming Active
        this.perfLog.start();
    }

    public void deliverNotification(ExtensibilityType message) {
        JobStatusType jobStatus = null;
        try {
            jobStatus = (JobStatusType) AnyHelper.getAsSingleObject(
                AnyHelper.getAsServiceDataValues(message),
                JobStatusType.class);
        } catch (Exception e) {
            logger.error("unabled to get message as service data", e);
            return;
        }
        JobStateType jobState = jobStatus.getJobState();

        if (   jobState.equals(JobStateType.Done)
            || jobState.equals(JobStateType.Failed)) {
            //start timming Active
            this.perfLog.stop(jobState.toString());
            this.harness.notifyCompleted();
        } else
        if (jobState.equals(JobStateType.Active)) {
            //start timming Active
            this.perfLog.stop("Active");

            //start timming Done
            this.perfLog.start();
        }
    }

    public void finalize() {
        //unsubscribe for notifications
        try {
            unsubscribeForNotifications();
        } catch (Exception e) {
            logger.error("unable to unsubscribe for MJS notifications", e);
        }

        //destroy MJS instance
        try {
            ManagedJobPortType managedJob = this.mjsLocator.getManagedJobPort(
                this.mjsLocator.getGSR().getHandle());
            managedJob.destroy();
        } catch (RemoteException re) {
            logger.error("unable to destroy MJS instance", re);
        }
    }

}
