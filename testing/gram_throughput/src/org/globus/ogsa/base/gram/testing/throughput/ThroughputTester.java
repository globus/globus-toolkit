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
        this.jobList = new SingleJobThread[this.count];
        this.jobPhaseState = new int[this.count];
        this.createdCount = 0;

        this.perfLog.start();

        for (int i=0; i<this.count; i++) {
            this.jobList[i] = new SingleJobThread(this, i);
            new Thread(this.jobList[i]).start();
        }

        while (this.createdCount < this.count) {
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
        this.startedCount = 0;

        this.perfLog.start();

        for (int i=0; i<this.count; i++) {
            this.jobList[i].start();
        }

        while (this.startedCount < this.count) {
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
        this.perfLog.start();

        while (this.completedCount < this.count) {
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

    public static void main(String[] args) {
        ThroughputTester harness = new ThroughputTester();
        harness.setFactoryUrl(args[0]);
        harness.setRslFile(args[1]);
        harness.setCount(Integer.parseInt(args[2]));

        harness.createAll();

        harness.startAll();
    }
}
