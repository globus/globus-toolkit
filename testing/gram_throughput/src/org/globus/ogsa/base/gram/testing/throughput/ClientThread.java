package org.globus.ogsa.base.gram.testing.throughput;

import java.io.File;
import java.io.FileReader;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.axis.message.MessageElement;
import org.apache.axis.utils.XMLUtils;
import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.axis.MessageContext;

import org.globus.axis.gsi.GSIConstants;
import org.globus.gram.GramException;
import org.globus.gsi.proxy.IgnoreProxyPolicyHandler;
import org.globus.ogsa.base.gram.types.JobStateType;
import org.globus.ogsa.handlers.GrimProxyPolicyHandler;
import org.globus.ogsa.impl.base.gram.client.GramJob;
import org.globus.ogsa.impl.base.gram.client.GramJobListener;
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
import org.globus.ogsa.utils.PerformanceLog;
import org.globus.ogsa.wsdl.GSR;

import org.gridforum.ogsi.Factory;
import org.gridforum.ogsi.GridService;
import org.gridforum.ogsi.HandleType;
import org.gridforum.ogsi.OGSIServiceGridLocator;
import org.gridforum.ogsi.OGSIServiceLocator;
import org.gridforum.ogsi.LocatorType;
import org.gridforum.ogsi.ExtensibilityType;

import org.ietf.jgss.GSSException;

public class ClientThread
    extends                         ServicePropertiesImpl
    implements                      Runnable,
                                    GramJobListener {

    static Log logger = LogFactory.getLog(ClientThread.class.getName());
    static int instanceCount = 0;
    static Object InstanceCountMonitor = new Object();

    ThroughputTester harness = null;
    int clientIndex = -1;
    boolean started = false;
    boolean completed = false;
    Vector jobs = null;
    int createdCount = 0;
    int completedCount = 0;

    PerformanceLog perfLog = new PerformanceLog(
        ClientThread.class.getName());

    public ClientThread(ThroughputTester harness) {
        synchronized (ClientThread.InstanceCountMonitor) {
            this.clientIndex = ClientThread.instanceCount;
            ClientThread.instanceCount++;
        }

        this.harness = harness;
    }

    public int getIndex() {
        return this.clientIndex;
    }

    // This method is invoked once each time the stress target is run
    // with this class
    synchronized public void run() {
        if (logger.isDebugEnabled()) {
            logger.debug("running client thread #" + this.clientIndex);
        }

        int load = this.harness.getLoad();
        this.jobs = new Vector(load);

        //start timing acutal duration
        if (logger.isDebugEnabled()) {
            logger.debug("perf log start [finished]");
        }
        this.perfLog.start();

        //maintain load
        while (!this.harness.isDurationElapsed()) {
            if (logger.isDebugEnabled()) {
                logger.debug("# created (outer loop): " + this.createdCount);
                logger.debug("# completed (outer loop): " + this.completedCount);
            }
            //use chached created count so we don't get stuck in this next loop
            int tmpCompletedCount = this.completedCount;
            while ((this.createdCount - tmpCompletedCount) < load) {
                if (logger.isDebugEnabled()) {
                    logger.debug("# created: " + this.createdCount);
                    logger.debug("# completed: " + this.completedCount);
                }
                try {
                    addJob();
                } catch (Exception e) {
                    logger.error("failed to add job", e);
                    this.createdCount--;
                }
            }

            try {
                wait(15000);
            } catch (InterruptedException ie) { }
        }

        logger.debug ("waiting for any outstanding jobs to finish...");

        //wait for jobs to finish
        while (this.completedCount < this.createdCount) {
            logger.debug ("Created: " + this.createdCount);
            logger.debug ("Completed: " + this.completedCount);
            try {
                wait(2000);
            } catch (InterruptedException ie) { }
        }

        //stop timing actual duration
        this.perfLog.stop("finished");

        //pass total number of jobs completed by this client back to harness
        this.harness.notifyCompleted(this.clientIndex, this.completedCount);
    }

    protected void addJob() throws GramException, GSSException {
        if (logger.isDebugEnabled()) {
            logger.debug("adding job to client #" + this.clientIndex);
        }
        
        GramJob job = new GramJob(this.harness.getRsl());
        this.jobs.add(job);
        job.addListener(this);
        job.request(this.harness.getFactoryUrl());

        if (logger.isDebugEnabled()) {
            logger.debug("starting job just added to client #"
                        + this.clientIndex);
        }
        job.start();

        this.createdCount++;
    }

    public void statusChanged(GramJob job) {
        String status = job.getStatusAsString();
        if (status.equals(JobStateType._Done)) {
            this.jobs.remove(job);
            try {
                job.destroy();
            } catch (Exception e) {
                logger.error("unable to destroy job", e);
            }
            this.completedCount++;
        } else
        if (status.equals(JobStateType._Failed)) {
            logger.error("a job failed with handle " + job.getHandle());
            this.jobs.remove(job);
            try {
                job.destroy();
            } catch (Exception e) {
                logger.error("unable to destroy job", e);
            }
            this.createdCount--;
        }
    }
}
