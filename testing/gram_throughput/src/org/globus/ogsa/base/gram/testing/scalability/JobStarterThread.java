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
import org.globus.ogsa.base.gram.types.FaultType;
import org.globus.ogsa.base.gram.types.JobStateType;
import org.globus.ogsa.base.gram.types.JobStatusType;
import org.globus.ogsa.handlers.GrimProxyPolicyHandler;
import org.globus.ogsa.impl.base.gram.utils.FaultUtils;
import org.globus.ogsa.impl.base.gram.utils.rsl.GramJobAttributes;
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

public class JobStarterThread
    extends                         ServicePropertiesImpl
    implements                      Runnable,
                                    NotificationSinkCallback {

    static Log logger = LogFactory.getLog(JobStarterThread.class.getName());
    static final Object RSL_MONITOR;
    static {
        RSL_MONITOR = new Object();
    }

    ScalabilityTester harness = null;
    String factoryUrl = null;
    Element rsl = null;
    ManagedJobServiceGridLocator mjsLocator = null;
    NotificationSinkManager notificationSinkManager = null;
    String notificationSinkId = null;
    int jobIndex = -1;
    boolean completed = false;

    public JobStarterThread(ScalabilityTester harness, int jobIndex) {
        this.harness = harness;
        this.jobIndex = jobIndex;
        this.factoryUrl = this.harness.getFactoryUrl();
        if (logger.isDebugEnabled()) {
            logger.debug("Factory URL: " + this.factoryUrl);
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
            abort("unable to create MJS instance", e);
            return;
        }

        //do actual start call on job
        try {
            startService();
        } catch (Exception e) {
            abort("unable to start MJS instance", e);
            return;
        }
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

        LocatorType gshHolder = null;
        synchronized (RSL_MONITOR) {
            //retrieve, parse, and validate the RSL
            File file = new File(this.harness.getRslFile());
            RslParser rslParser = RslParserFactory.newRslParser();
            try {
                this.rsl = rslParser.parse(new FileReader(file));
                GramJobAttributes rslAttributes = new GramJobAttributes(this.rsl);
                rslAttributes.setSubstitutionDefinition(
                    "JOB_INDEX",
                    "<rsl:urlElement value=\"" + String.valueOf(jobIndex) + "\"/>");
            } catch (Exception e) {
                abort("unable to read RSL file", e);
            }

            ExtensibilityType creationParameters
                = AnyHelper.getExtensibility(this.rsl);
            gshHolder = gridServiceFactory.createService(creationParameters);
            this.harness.notifyCreated(this.jobIndex, gshHolder.getHandle());
            this.rsl = null;
        }
        this.mjsLocator = new ManagedJobServiceGridLocator();
        //This next step caches the GSR in the locator for use later
        ManagedJobPortType managedJob
            = this.mjsLocator.getManagedJobPort(gshHolder);

        /*
        try {
            subscribeForNotifications();
        } catch (Exception e) {
            throw new Exception("unable to subscribe for MJS notifications", e);
        }
        */
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
            abort("unable to get MJS reference", e);
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
            abort("unable to start MJS instance", e);
            return;
        }
        managedJob = null;

       this.harness.notifyStarted(this.jobIndex);

       if (logger.isDebugEnabled()) {
           logger.debug("notified harness that I started");
       }
    }

    protected void abort(String errorMessage) {
        abort(errorMessage, null);
    }
    
    protected void abort(String errorMessage, Exception e) {
        if (e != null) {
            logger.error(errorMessage, e);
        } else {
            logger.error(errorMessage);
        }
        this.harness.notifyError();
        jobIndex = -1;
        cleanup();
    }
}
