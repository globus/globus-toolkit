package org.globus.ogsa.base.gram.testing.throughput;

import java.util.Hashtable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.ogsa.utils.PerformanceLog;

public class ThroughputTester {

    static Log logger = LogFactory.getLog(ThroughputTester.class.getName());

    String factoryUrl = null;
    String rslFile = null;
    int load = 1;
    int parallelism = 1;
    long duration = 1;
    SingleJobThread[] jobList = null;
    int[] jobPhaseState = null;
    boolean[] completedList = null;
    int createdCount = 0;
    int startedCount = 0;
    int completedCount = 0;
    int stoppedCount = 0;

    PerformanceLog perfLog = new PerformanceLog(
        ThroughputTester.class.getName());
    PerformanceLog completePerfLog = new PerformanceLog(
        ThroughputTester.class.getName() + ".complete");

    public ThroughputTester() { }

    public synchronized void run() {
        createAll();

        startAll();

        waitForAllToComplete();

        cleanupAll();
    }

    protected void createAll() {
        this.jobList = new SingleJobThread[this.load];
        this.jobPhaseState = new int[this.load];

        //START TIMMING createService
        if (logger.isDebugEnabled()) {
            logger.debug("creating " + this.load + " job(s)");
            logger.debug("perf log start [createService]");
        }
        this.perfLog.start();

        for (int i=0; i<this.load; i++) {
            this.jobList[i] = new SingleJobThread(this, i);
            new Thread(this.jobList[i]).start();
        }

        int oldCreatedCount = -1;
        while (this.createdCount < this.load) {
            if (logger.isDebugEnabled()) {
                if (oldCreatedCount != this.createdCount) {
                    logger.debug("waiting for "
                                + (this.load - this.createdCount)
                                + " job(s) to be created");
                    oldCreatedCount = this.createdCount;
                }
            }

            try {
                wait(5000);
            } catch (Exception e) {
                logger.error("unabled to wait", e);
            }
        }

        //STOP TIMMING createService
        this.perfLog.stop("createService");
        if (logger.isDebugEnabled()) {
            logger.debug("all jobs created");
        }
    }

    protected void startAll() {
        if (logger.isDebugEnabled()) {
            logger.debug("starting " + this.load + " job(s)");
        }

        //START TIMMING start
        if (logger.isDebugEnabled()) {
            logger.debug("starting " + this.load + " job(s)");
            logger.debug("perf log start [start]");
        }
        this.perfLog.start();

        for (int i=0; i<this.jobList.length; i++) {
            if (this.jobList[i].getIndex() >= 0) {
                this.jobList[i].start();
            }
        }

        boolean startedTimmingComplete = false;
        int oldStartedCount = -1;
        while (this.startedCount < this.load) {
            if (logger.isDebugEnabled()) {
                if (oldStartedCount != this.startedCount) {
                    logger.debug("waiting for "
                                + (this.load - this.startedCount)
                                + " job(s) to be started");
                    oldStartedCount = this.startedCount;
                }
            }

            try {
                wait(5000);
            } catch (Exception e) {
                logger.error("unabled to wait", e);
            }

            if (!startedTimmingComplete) {
                //START TIMMING complete
                if (logger.isDebugEnabled()) {
                    logger.debug("starting " + this.load + " job(s)");
                    logger.debug("perf log start [start]");
                }
                this.completePerfLog.start();
                startedTimmingComplete = true;
            }
        }

        //STOP TIMMING start
        this.perfLog.stop("start");
        if (logger.isDebugEnabled()) {
            logger.debug("all jobs started");
        }
    }

    protected void waitForAllToComplete() {
        this.completedList = new boolean[this.load];
        for (int index=0; index<this.load; index++) {
            this.completedList[index] = false;
        }
        int oldCompletedCount = -1;
        while (this.completedCount < this.load) {
            if (logger.isDebugEnabled()) {
                if (oldCompletedCount != this.completedCount) {
                    logger.debug("waiting for "
                                + (this.load - this.completedCount)
                                + " job(s) to be completed");
                    oldCompletedCount = this.completedCount;
                }
            }

            try {
                wait(5000);
            } catch (Exception e) {
                logger.error("unabled to wait", e);
            }
            this.completedCount = 0;
            for (int index=0; index<this.load; index++) {
                if (this.completedList[index]) {
                    this.completedCount++;
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Waiting for job #" + index);
                    }
                }
            }
        }

        //STOP TIMMING start
        this.completePerfLog.stop("complete");
        if (logger.isDebugEnabled()) {
            logger.debug("all jobs completed");
        }

        for (int index=0; index<this.load; index++) {
            if (!this.completedList[index]) {
                if (logger.isDebugEnabled()) {
                    logger.debug("False notify for job #" + index);
                }
            }
        }
    }

    protected void cleanupAll() {
        //send signal to all job threads to cleanup and exit
        for (int i=0; i<this.jobList.length; i++) {
            this.jobList[i].stop();
        }

        int oldStoppedCount = -1;
        while (this.stoppedCount < this.load) {
            if (logger.isDebugEnabled()) {
                if (oldStoppedCount != this.stoppedCount) {
                    logger.debug("waiting for "
                                + (this.load - this.stoppedCount)
                                + " job(s) to be stopped");
                    oldStoppedCount = this.stoppedCount;
                }
            }

            try {
                wait(5000);
            } catch (Exception e) {
                logger.error("unabled to wait", e);
            }
        }

        this.perfLog.stop("complete");

        if (logger.isDebugEnabled()) {
            logger.debug("all jobs stopped");
        }
    }

    synchronized void notifyError() {
        this.load--;
        notifyAll();
    }

    synchronized void notifyCreated(int jobIndex) {
        if (logger.isDebugEnabled()) {
            logger.debug("got created signal from job #" + jobIndex);
        }
        this.createdCount++;
        notifyAll();
    }

    synchronized void notifyStarted(int jobIndex) {
        if (logger.isDebugEnabled()) {
            logger.debug("got started signal from job #" + jobIndex);
        }
        this.startedCount++;
        notifyAll();
    }

    synchronized void notifyCompleted(int jobIndex) {
        if (logger.isDebugEnabled()) {
            logger.debug("got completed signal from job #" + jobIndex);
        }
        //this.completedCount++;
        this.completedList[jobIndex] = true;
        notifyAll();
    }

    synchronized void notifyStopped(int jobIndex) {
        if (logger.isDebugEnabled()) {
            logger.debug("got stopped signal from job #" + jobIndex);
        }
        this.stoppedCount++;
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

    public void setLoad(int load) {
        this.load = load;
    }

    public int getLoad() {
        return this.load;
    }

    public void setParallelism(int parallelism) {
        this.parallelism = parallelism;
    }

    public int getParallelism() {
        return this.parallelism;
    }

    public void setDuration(long duration) {
        this.duration = duration;
    }

    public long getDuration() {
        return this.duration;
    }

    public static void printUsage(String customMessage) {
        StringBuffer usageMessage = new StringBuffer(customMessage);
        usageMessage.append("\nUsage:");
        usageMessage.append("\njava [JAVA OPTIONS] ");
        usageMessage.append(ThroughputTester.class.getName());
        usageMessage.append(" [OPTIONS]\n\nOPTIONS:\n");
        usageMessage.append("\n\t--help\t\t\t\tPrint this usage message.");
        usageMessage.append("\n\t--factory <factory URL>\t\t(M)MJFS URL");
        usageMessage.append("\n\t--file <RSL file>\t\tRSL file name");
        usageMessage.append("\n\t--load <load>\t\t\tPer-thread job load");
        usageMessage.append("\n\t--parallelism <parallelism>");
        usageMessage.append("\tNumber of client threads");
        usageMessage.append("\n\t--duration <duration>");
        usageMessage.append("\t\tLoad maintenance duratuon");
        System.out.println(usageMessage.toString());
    }

    public static void main(String[] args) {
        if (logger.isDebugEnabled()) {
            logger.debug("argument count: " + args.length);
        }
        Hashtable options = new Hashtable();
        options.put("help", new Boolean(false));
        options.put("factory", "");
        options.put("file", "");
        options.put("load", "1");
        options.put("parallelism", "1");
        options.put("duration", "1");
        String argName = null;
        String argValue = null;
        for (int index=0; index<args.length; index++) {
            if (logger.isDebugEnabled()) {
                logger.debug("argument #" + index + ": " + args[index]);
            }
            if (args[index].startsWith("--")) {
                argName = args[index].substring(2);
                if (logger.isDebugEnabled()) {
                    logger.debug("argument name: " + argName);
                }
                index++;
                try {
                    argValue = args[index];
                } catch(ArrayIndexOutOfBoundsException e) {
                    Object defaultValue = options.get(argName);
                    if ((defaultValue != null) &&
                        (defaultValue instanceof String)) {
                        ThroughputTester.printUsage(
                            "Error: value expected for " + argName);
                        System.exit(1);
                    }
                }
                if (logger.isDebugEnabled()) {
                    logger.debug("argument value: " + argName);
                }
                if (((argValue != null) && (argValue.startsWith("--")))
                    || (argValue == null)) {
                    index--;
                    options.put(argName, new Boolean(true));
                } else {
                    options.put(argName, argValue);
                }
            } else if (args[index].startsWith("-")) {
                ThroughputTester.printUsage(
                    "Single-dash options not supported");
                System.exit(1);
            } else {
                ThroughputTester.printUsage(
                    "Error: unexpected argument " + argName);
                System.exit(1);
            }
            argValue = null;
        }
        if (((Boolean)options.get("help")).booleanValue()) {
            ThroughputTester.printUsage("-- Help --");
            System.exit(0);
        }
        if (((String)options.get("factory")).length() < 0) {
            ThroughputTester.printUsage("Error: --factory <url> not specified");
            System.exit(1);
        }
        if (((String)options.get("file")).length() < 0) {
            ThroughputTester.printUsage(
                "Error: --file <rsl file> not specified");
            System.exit(1);
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Factory URL: " + options.get("factory"));
            logger.debug("RSL File: " + options.get("file"));
            logger.debug("Per-Thread Job Load: " + options.get("load"));
            logger.debug("Parallelism: " + options.get("parallelism"));
            logger.debug("Load Maintenance Duration: "
                        +options.get("duration"));
        }

        ThroughputTester harness = new ThroughputTester();
        harness.setFactoryUrl((String)options.get("factory"));
        harness.setRslFile((String)options.get("file"));
        harness.setLoad(Integer.parseInt((String)options.get("load")));

        harness.setParallelism(
            Integer.parseInt((String)options.get("parallelism")));
        harness.setDuration(Long.parseLong((String)options.get("duration")));

        //harness.run();
    }
}
