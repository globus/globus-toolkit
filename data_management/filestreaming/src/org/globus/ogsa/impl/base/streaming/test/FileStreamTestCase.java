
/**
 * FileStreamTestCase.java
 *
 * This file was auto-generated from WSDL
 * by the Apache WSIF WSDL2Java emitter.
 */

package org.globus.ogsa.impl.base.streaming.test;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.Iterator;
import javax.xml.rpc.Stub;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import junit.textui.TestRunner;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.axis.gsi.GSIConstants;
import org.globus.gsi.gssapi.auth.SelfAuthorization;
import org.globus.gsi.gssapi.GSSConstants;

import org.globus.ogsa.base.streaming.FileStreamOptionsType;
import org.globus.ogsa.base.streaming.FileStreamOptionsWrapperType;
import org.globus.ogsa.base.streaming.FileStreamFactoryOptionsType;
import org.globus.ogsa.base.streaming.FileStreamFactoryOptionsWrapperType;
import org.globus.ogsa.base.streaming.FileStreamPortType;
import org.globus.ogsa.base.streaming.service.FileStreamServiceGridLocator;
import org.globus.ogsa.impl.security.authentication.Constants;
import org.globus.ogsa.server.test.GridTestCase;
import org.globus.ogsa.server.test.TestServer;
import org.globus.ogsa.utils.AnyHelper;
import org.globus.ogsa.utils.GridServiceFactory;
import org.globus.ogsa.wsdl.GSR;
import org.gridforum.ogsi.ExtensibilityType;
import org.gridforum.ogsi.Factory;
import org.gridforum.ogsi.FaultType;
import org.gridforum.ogsi.GridService;
import org.gridforum.ogsi.LocatorType;
import org.gridforum.ogsi.OGSIServiceGridLocator;
import org.gridforum.ogsi.ReferenceType;

public class FileStreamTestCase extends GridTestCase {
    static Log logger = LogFactory.getLog(FileStreamTestCase.class.getName());

    private static final String FSFF_BASE_PATH
        = "base/streaming/FileStreamFactoryFactoryService";
    private static final String FSF_INSTANCE_ID = "testFileStreamFactory";
    private static final String FSS_INSTANCE_ID = "testFileStream";

    private static final String TEST_SOURCE_FILE
        = System.getProperty("user.dir")
        + "/"
        + "test-reports/test_fss_source_file";
    private static final String TEST_DESTINATION_FILE
        = System.getProperty("user.dir")
        + "/"
        + "test-reports/test_fss_dest_file";
    private static final String TEST_DESTINATION_URL
        = "file:///" + TEST_DESTINATION_FILE;
    private static final String[] TEST_PATTERNS
        = {"~~~~!!!!@@@@####$$$$%%%%^^^^&&&&****(((())))____++++",
           "~!@#$%^&*()_++_)(*&^%$#@!~~!@#$%^&*()_++_)(*&^%$#@!~"};

    private static LocatorType factoryHandleLocator = null;

    private static OGSIServiceGridLocator gridServiceLocator
        = new OGSIServiceGridLocator();

    public FileStreamTestCase(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(FileStreamTestCase.class);
    }

    private void createServer() throws RemoteException, FaultType {
        //create a file stream factory
        String serviceFactoryUrl
            = TEST_SERVER.getBaseURL()
            + FSFF_BASE_PATH;

        GridServiceFactory fileStreamFactoryFactory = null;
        try {
            fileStreamFactoryFactory = new GridServiceFactory(
                    this.gridServiceLocator.getFactoryPort(
                        new URL(serviceFactoryUrl)));
        } catch (MalformedURLException murle) {
            logger.error("failed to locate factory", murle);
            return;
        }

        FileStreamFactoryOptionsWrapperType factoryOptionsWrapper
            = new FileStreamFactoryOptionsWrapperType();
        FileStreamFactoryOptionsType factoryOptions
            = new FileStreamFactoryOptionsType();
        factoryOptions.setSourcePath(TEST_SOURCE_FILE);
        factoryOptionsWrapper.setFileStreamFactoryOptions(factoryOptions);
        ExtensibilityType creationParameters
            = AnyHelper.getExtensibility(factoryOptionsWrapper);

        this.factoryHandleLocator
            = fileStreamFactoryFactory.createService(
                    null, FSF_INSTANCE_ID, creationParameters);

        GSR gsr = GSR.newInstance(this.factoryHandleLocator);
        logger.debug("FSF Handle: " + gsr.getHandle());

    }

    private void destroyServer() throws RemoteException, FaultType {
        //destroy the file stream factory
        GridService fileStreamFactory = this.gridServiceLocator.getFactoryPort(
                    this.factoryHandleLocator);
        fileStreamFactory.destroy();
        logger.debug("FSF Destroyed");
    }

    private FileStreamPortType createFileStream() throws RemoteException  {
        GridServiceFactory fileStreamFactory = new GridServiceFactory(
                this.gridServiceLocator.getFactoryPort(
                    this.factoryHandleLocator));
        fileStreamFactory.getStub()._setProperty(
                Constants.MSG_SEC_TYPE,
                Constants.SIGNATURE);
        fileStreamFactory.getStub()._setProperty(
                GSIConstants.GSI_AUTHORIZATION,
                SelfAuthorization.getInstance());
        fileStreamFactory.getStub()._setProperty(
                GSIConstants.GSI_MODE,
                GSIConstants.GSI_MODE_LIMITED_DELEG);

        FileStreamOptionsWrapperType fileStreamOptionsWrapper
            = new FileStreamOptionsWrapperType();
        FileStreamOptionsType fileStreamOptions
            = new FileStreamOptionsType();
        fileStreamOptions.setDestinationUrl(TEST_DESTINATION_URL);
        fileStreamOptions.setOffset(0);
        fileStreamOptionsWrapper.setFileStreamOptions(fileStreamOptions);
        ExtensibilityType creationParameters
            = AnyHelper.getExtensibility(fileStreamOptionsWrapper);

        logger.debug("creating file stream...");
        LocatorType fileStreamHandleLocator
            = fileStreamFactory.createService(
                    null, FSS_INSTANCE_ID, creationParameters);

        GSR gsr = GSR.newInstance(fileStreamHandleLocator);
        logger.debug("FSS Handle: " + gsr.getHandle());

        FileStreamServiceGridLocator fileStreamLocator
            = new FileStreamServiceGridLocator();
        FileStreamPortType fileStream = fileStreamLocator.getFileStreamPort(
                            fileStreamHandleLocator);

        return fileStream;
    }

    private void sendTestPattern(int testPatternIndex) {
        try {
            //BufferedWriter writer = new BufferedWriter(
            FileWriter writer =
                    new FileWriter(TEST_SOURCE_FILE);
            writer.write(TEST_PATTERNS[testPatternIndex]);
            writer.flush();
            writer.close();
        } catch (IOException ioe) {
            logger.error("source file write failed", ioe);
        }
    }

    private void assertTestPatternTransmitted(int testPatternIndex) {
        try {
            BufferedReader reader = new BufferedReader(
                    new FileReader(TEST_DESTINATION_FILE));
            String line = reader.readLine();
            reader.close();

            assertTrue(line.equals(TEST_PATTERNS[testPatternIndex]));
        } catch (IOException ioe) {
            logger.error("destination file read failed", ioe);
        }
    }

    public void testFileStream() {
        try {
            createServer();
        } catch (Exception e) {
            logger.error("problem creating FileStreamFactory", e);
            return;
        }

        FileStreamPortType fileStream = null;

        try {
            fileStream = createFileStream();
        } catch (RemoteException re) {
            logger.error("file stream creation failed", re);
            return;
        }

       ((Stub) fileStream)._setProperty(Constants.MSG_SEC_TYPE,
                                        Constants.SIGNATURE);
       ((Stub) fileStream)._setProperty(GSIConstants.GSI_AUTHORIZATION,
                                        SelfAuthorization.getInstance());

        sendTestPattern(0);

        try {
            fileStream.start();
        } catch (RemoteException re) {
            logger.error("file stream start failed", re);
            return;
        }

        try {
            fileStream.stop();
        } catch (RemoteException re) {
            logger.error("file stream stop failed", re);
            return;
        }

        assertTestPatternTransmitted(0);

        try {
            fileStream.destroy();
        } catch (RemoteException re) {
            logger.error("file stream destruction failed", re);
            return;
        }

        logger.debug("FSS Destroyed");

        try {
            destroyServer();
        } catch (Exception e) {
            logger.error("problem destroying FileStreamFactory", e);
        }
    }

    public static void main(String[] args) {
        TestRunner.run(suite());
    }
}
