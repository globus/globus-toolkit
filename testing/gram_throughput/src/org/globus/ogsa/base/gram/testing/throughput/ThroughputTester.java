package org.globus.ogsa.base.gram.testing.throughput;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.URL;
import java.util.Hashtable;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.ogsa.impl.base.gram.utils.rsl.JobAttributes;
import org.globus.ogsa.impl.base.gram.utils.rsl.RslParser;
import org.globus.ogsa.impl.base.gram.utils.rsl.RslParserFactory;
import org.globus.ogsa.utils.PerformanceLog;

public class ThroughputTester {

    static Log logger = LogFactory.getLog(ThroughputTester.class.getName());

    URL factoryUrl = null;
    String rslFile = null;
    String rsl = null;
    int load = 1;
    int parallelism = 1;
    long duration = 1;
    ClientThread[] clients = null;
    int completedCount = 0;
    int jobGrandTotal = 0;
    boolean durationElapsed = false;

    PerformanceLog perfLog = new PerformanceLog(
        ThroughputTester.class.getName());
    PerformanceLog completePerfLog = new PerformanceLog(
        ThroughputTester.class.getName() + ".complete");

    public ThroughputTester() { }

    public synchronized void run() {
        //retrieve, parse, and validate the RSL
        BufferedReader rslReader = null;
        StringBuffer rslBuffer = null;
        try {
            rslReader = new BufferedReader(new FileReader(rslFile));
            rslBuffer = new StringBuffer();
            String rslLine = rslReader.readLine();
            while (rslLine != null) {
                rslBuffer.append(rslLine);
                rslLine = rslReader.readLine();
            }
        } catch (java.io.IOException ioe) {
            logger.error("unable to read rsl file " + rslFile, ioe);
            System.exit(1);
        } finally {
            if (rslReader != null) {
                try {
                    rslReader.close();
                } catch (Exception e) { }
            }
        }
        this.rsl = rslBuffer.toString();

        //start timing actual duration
        long startTime = System.currentTimeMillis();

        this.clients = new ClientThread[this.parallelism];
        for (int index=0; index<this.clients.length; index++) {
            this.clients[index] = new ClientThread(this);
            new Thread(this.clients[index]).start();
        }

        //start a timer to stop the madness when the time is right
        QuitTimerTask quitTimerTask = new QuitTimerTask(this);
        Timer quitTimer = new Timer();
        quitTimer.schedule(quitTimerTask, this.duration);

        try {
            //wait for all clients to checkin with their job totals
            wait();
        } catch (Exception e) {
            logger.error("wait() canceled unexpectedly", e);
        }

        //calculate actual duration and jobs per minute across all clients
        logger.info("Total Jobs Submitted: " + this.jobGrandTotal);
        long actualDuration = System.currentTimeMillis() - startTime;
        logger.info("Actual Duration (seconds): " + actualDuration);
        double durationInMinutes = ((double)actualDuration) / 60000;
        logger.info("Actual Duration (minutes): " + durationInMinutes);
        double jobsPerMinute = Math.round(
            this.jobGrandTotal / durationInMinutes);
        logger.info("Jobs Per Minute: " + jobsPerMinute);

        System.exit(0);
    }

    synchronized void notifyError() {
        logger.error("unable to proceed with test");
        System.exit(1);
    }

    synchronized void notifyCompleted(int clientIndex, int jobTotal) {
        if (logger.isDebugEnabled()) {
            logger.debug("got completed signal from client #" + clientIndex);
        }
        this.completedCount++;
        this.jobGrandTotal += jobTotal;

        if (this.completedCount == this.clients.length) {
            notify(); //notify wait() at end of run()
        }
    }

    public void setFactoryUrl(URL factoryUrl) {
        this.factoryUrl = factoryUrl;
    }

    public URL getFactoryUrl() {
        return this.factoryUrl;
    }

    public void setRslFile(String rslFile) {
        this.rslFile = rslFile;
    }

    public String getRslFile() {
        return this.rslFile;
    }

    public String getRsl() {
        return this.rsl;
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

    public boolean isDurationElapsed() {
        return this.durationElapsed;
    }

    void setDurationElapsed(boolean durationElapsed) {
        this.durationElapsed = durationElapsed;
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
        URL factoryUrl = null;
        try {
            factoryUrl = new URL((String)options.get("factory"));
        } catch (Exception e) {
            logger.error("invalid factory URL: "
                        + (String)options.get("factory"));
            System.exit(1);
        }
        harness.setFactoryUrl(factoryUrl);
        harness.setRslFile((String)options.get("file"));
        harness.setLoad(Integer.parseInt((String)options.get("load")));

        harness.setParallelism(
            Integer.parseInt((String)options.get("parallelism")));
        harness.setDuration(Long.parseLong((String)options.get("duration")));

        harness.run();
    }
}

class QuitTimerTask extends TimerTask {
    ThroughputTester harness = null;
    public QuitTimerTask(ThroughputTester harness) {
        this.harness = harness;
    }

    public void run() {
        this.harness.setDurationElapsed(true);
    }
}
