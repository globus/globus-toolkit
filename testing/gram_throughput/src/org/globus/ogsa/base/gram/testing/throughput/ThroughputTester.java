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
    int createdCount = -1;
    int startedCount = -1;
    int completedCount = -1;

    PerformanceLog perfLog = new PerformanceLog(
        ThroughputTester.class.getName());

    public ThroughputTester() { }

    public void createAll() {
        if (logger.isDebugEnabled()) {
            logger.debug("creating " + this.count + " job(s)");
        }
        this.jobList = new SingleJobThread[this.count];
        this.jobPhaseState = new int[this.count];
        this.createdCount = 0;

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
            synchronized (this) {
                //avoid deadlock by checking once more when we have the lock
                if (this.createdCount < this.count) {
                    try {
                        wait();
                    } catch (Exception e) {
                        logger.error("unabled to wait", e);
                    }
                }
            }
        }

        this.perfLog.stop("createService");
    }

    synchronized void notifyCreated() {
        this.createdCount++;
        notifyAll();
    }

    public void startAll() {
        if (logger.isDebugEnabled()) {
            logger.debug("starting " + this.count + " job(s)");
        }
        this.startedCount = 0;

        if (logger.isDebugEnabled()) {
            logger.debug("perf log start [start]");
        }
        this.perfLog.start();

        for (int i=0; i<this.count; i++) {
            this.jobList[i].start();
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
            synchronized (this) {
                //avoid deadlock by checking once more when we have the lock
                if (this.startedCount < this.count) {
                    try {
                        wait();
                    } catch (Exception e) {
                        logger.error("unabled to wait", e);
                    }
                }
            }
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
            synchronized (this) {
                //avoid deadlock by checking once more when we have the lock
                if (this.completedCount < this.count) {
                    try {
                        wait();
                    } catch (Exception e) {
                        logger.error("unabled to wait", e);
                    }
                }
            }
        }

        this.perfLog.stop("complete");
    }

    synchronized void notifyStarted() {
        this.startedCount++;
        notifyAll();
    }

    synchronized void notifyCompleted() {
        this.completedCount++;
        notifyAll();
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
