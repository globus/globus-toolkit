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
import java.io.BufferedWriter;
import java.io.FileWriter;

import org.globus.ogsa.tools.ant.StressTest;
import org.globus.ogsa.utils.PerformanceLog;

public class JobStopperThread
    extends                         ServicePropertiesImpl
    implements                      Runnable {

    static Log logger = LogFactory.getLog(JobStopperThread.class.getName());
    static final Object RSL_MONITOR;
    static {
        RSL_MONITOR = new Object();
    }

    ScalabilityTester harness = null;
    int jobIndex = -1;
    String jobHandle = null;

    public JobStopperThread(
            ScalabilityTester           harness,
            int                         jobIndex,
            String                      jobHandle) {
        this.harness = harness;
        this.jobIndex = jobIndex;
        this.jobHandle = jobHandle;
    }

    public int getIndex() {
        return this.jobIndex;
    }

    // This method is invoked once each time the stress target is run
    // with this class
    synchronized public void run() {
        if (logger.isDebugEnabled()) {
            logger.debug("running job stopper thread");
        }

        GramJob job = new GramJob("");
        try {
            job.setHandle(this.jobHandle);
            job.destroy();
        } catch (Exception e) {
            logger.error("unabled to destroy job", e);
        }
    }
}
