package org.globus.ogsa.base.gram.testing.throughput;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.ogsa.utils.PerformanceLog;

public class ThroughputTester {

    static Log logger = LogFactory.getLog(ThroughputTester.class.getName());

    String factoryUrl = null;
    String rslFile = null;
    int count = 1;
    SingleJobThread[] jobList = null;
    int[] jobPhaseState = null;
    int createdCount = 0;
    int startedCount = 0;
    int completedCount = 0;
    int stoppedCount = 0;

    PerformanceLog perfLog = new PerformanceLog(
        ThroughputTester.class.getName());

    public ThroughputTester() { }

    public synchronized void createAll() {
        if (logger.isDebugEnabled()) {
            logger.debug("creating " + this.count + " job(s)");
        }
        this.jobList = new SingleJobThread[this.count];
        this.jobPhaseState = new int[this.count];

        if (logger.isDebugEnabled()) {
            logger.debug("perf log start [createService]");
        }
        this.perfLog.start();

        for (int i=0; i<this.count; i++) {
            this.jobList[i] = new SingleJobThread(this, i);
            new Thread(this.jobList[i]).start();
        }

        int oldCreatedCount = -1;
        while (this.createdCount < this.count) {
            if (logger.isDebugEnabled()) {
                if (oldCreatedCount != this.createdCount) {
                    logger.debug("waiting for "
                                + (this.count - this.createdCount)
                                + " job(s) to be created");
                    oldCreatedCount = this.createdCount;
                }
            }

            try {
                wait();
            } catch (Exception e) {
                logger.error("unabled to wait", e);
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("all jobs created");
        }

        this.perfLog.stop("createService");
    }

    synchronized void notifyError() {
        this.count--;
        notifyAll();
    }

    synchronized void notifyCreated() {
        this.createdCount++;
        notifyAll();
    }

    public synchronized void startAll() {
        if (logger.isDebugEnabled()) {
            logger.debug("starting " + this.count + " job(s)");
        }

        if (logger.isDebugEnabled()) {
            logger.debug("perf log start [start]");
        }
        this.perfLog.start();

        for (int i=0; i<this.jobList.length; i++) {
            if (this.jobList[i].getIndex() >= 0) {
                this.jobList[i].start();
            }
        }

        int oldStartedCount = -1;
        while (this.startedCount < this.count) {
            if (logger.isDebugEnabled()) {
                if (oldStartedCount != this.startedCount) {
                    logger.debug("waiting for "
                                + (this.count - this.startedCount)
                                + " job(s) to be started");
                    oldStartedCount = this.startedCount;
                }
            }

            try {
                wait();
            } catch (Exception e) {
                logger.error("unabled to wait", e);
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("all jobs started");
        }

        this.perfLog.stop("start");
        if (logger.isDebugEnabled()) {
            logger.debug("perf log start [complete]");
        }
        this.perfLog.start();

        int oldCompletedCount = -1;
        while (this.completedCount < this.count) {
            if (logger.isDebugEnabled()) {
                if (oldCompletedCount != this.completedCount) {
                    logger.debug("waiting for "
                                + (this.count - this.completedCount)
                                + " job(s) to be completed");
                    oldCompletedCount = this.completedCount;
                }
            }

            try {
                wait();
            } catch (Exception e) {
                logger.error("unabled to wait", e);
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("all jobs completed");
        }

        this.perfLog.stop("complete");

        //try { Thread.currentThread().sleep(2000); } catch (Exception e ) { }

        int oldStoppedCount = -1;
        while (this.stoppedCount < this.count) {
            if (logger.isDebugEnabled()) {
                if (oldStoppedCount != this.stoppedCount) {
                    logger.debug("waiting for "
                                + (this.count - this.stoppedCount)
                                + " job(s) to be stopped");
                    oldStoppedCount = this.stoppedCount;
                }
            }

            //send signal to all job threads to exit
            for (int i=0; i<this.jobList.length; i++) {
                this.jobList[i].stop();
            }

            try {
                wait();
            } catch (Exception e) {
                logger.error("unabled to wait", e);
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("all jobs stopped");
        }
    }

    synchronized void notifyStarted() {
        this.startedCount++;
        notify();
    }

    synchronized void notifyCompleted(int jobIndex) {
        this.completedCount++;
        notify();
    }

    synchronized void notifyStopped() {
        this.stoppedCount++;
        notify();
    }

    public void setFactoryUrl(String factoryUrl) {
        this.factoryUrl = factoryUrl;
    }

    public String getFactoryUrl() {
        return this.factoryUrl;
    }

    public void setRslFile(String rslFile) {
        this.rslFile = rslFile;
    }

    public String getRslFile() {
        return this.rslFile;
    }

    public void setCount(int count) {
        this.count = count;
    }

    public int getCount() {
        return this.count;
    }

    public static void printUsage(String customMessage) {
        StringBuffer usageMessage = new StringBuffer(customMessage);
        usageMessage.append("\nUsage:");
        usageMessage.append("\njava ... ");
        usageMessage.append(ThroughputTester.class.getName()).append(" \\");
        usageMessage.append("\n\t<factory URL> <RSL file> <job count>");
        System.out.println(usageMessage.toString());
    }

    public static void main(String[] args) {
        if (args.length == 1) {
            if (   args[0].equals("-h")
                || args[0].equals("--help")) {
                ThroughputTester.printUsage("-- Help --");
                System.exit(0);
            }

        }
        if (args.length != 3) {
            ThroughputTester.printUsage("Error: invalid number of arguments");
            System.exit(1);
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Factory URL: " + args[0]);
            logger.debug("RSL File: " + args[1]);
            logger.debug("Job Count: " + args[2]);
        }

        ThroughputTester harness = new ThroughputTester();
        harness.setFactoryUrl(args[0]);
        harness.setRslFile(args[1]);
        harness.setCount(Integer.parseInt(args[2]));

        harness.createAll();

        harness.startAll();
    }
}
