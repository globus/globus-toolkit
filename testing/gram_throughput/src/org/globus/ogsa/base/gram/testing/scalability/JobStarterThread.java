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
import org.globus.ogsa.impl.base.gram.client.GramJob;
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
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.StringWriter;

import org.globus.ogsa.tools.ant.StressTest;
import org.globus.ogsa.utils.PerformanceLog;

public class JobStarterThread
    extends                         ServicePropertiesImpl
    implements                      Runnable {

    static Log logger = LogFactory.getLog(JobStarterThread.class.getName());

    ScalabilityTester harness = null;
    String factoryUrl = null;
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

        GramJob job = null;
        //retrieve, parse, and validate the RSL
        String rsl = null;
        try {
            BufferedReader reader
               = new BufferedReader(new FileReader(this.harness.getRslFile()));
            StringWriter writer = new StringWriter();
            String line = reader.readLine();
            while (line != null) {
                writer.write(line);
                line = reader.readLine();
            }
            writer.close();
            reader.close();
            rsl = writer.toString();
        } catch (Exception e) {
            abort("unable to read RSL", e);
            return;
        }

        //create job
        if (logger.isDebugEnabled()) {
            logger.debug("creating job #" + this.jobIndex);
        }
        job = new GramJob(rsl);
        try {
            job.setSubstitutionDefinition(
                "JOB_INDEX",
                "<rsl:urlElement value=\"" + this.jobIndex + "\"/>");
            job.request(new URL(this.factoryUrl), true);
        } catch (Exception e) {
            abort("unable to create MJS instance", e);
            return;
        }
        if (logger.isDebugEnabled()) {
            logger.debug("created job #" + this.jobIndex);
        }
        this.harness.notifyCreated(
            this.jobIndex,
            job.getHandle().toString());

        //do actual start call on job
        if (logger.isDebugEnabled()) {
            logger.debug("starting job #" + this.jobIndex
                        +" with handle:\n" + job.getHandle());
        }
        try {
            job.start();
        } catch (Exception e) {
            abort("unable to start MJS instance", e);
            logger.error(e.getMessage());
            return;
        }
        if (logger.isDebugEnabled()) {
            logger.debug("started job #" + this.jobIndex);
        }
        this.harness.notifyStarted(this.jobIndex);
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
    }
}
