
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

import org.globus.axis.gsi.GSIConstants;
import org.globus.gsi.gssapi.auth.SelfAuthorization;

import org.globus.ogsa.base.streaming.FileStreamAttributes;
import org.globus.ogsa.base.streaming.FileStreamAttributesWrapper;
import org.globus.ogsa.base.streaming.FileStreamFactoryAttributes;
import org.globus.ogsa.base.streaming.FileStreamFactoryAttributesWrapper;
import org.globus.ogsa.base.streaming.FileStreamPortType;
import org.globus.ogsa.base.streaming.service.FileStreamServiceGridLocator;
import org.globus.ogsa.impl.security.authentication.Constants;
import org.globus.ogsa.server.test.TestServer;
import org.globus.ogsa.utils.AnyHelper;
import org.globus.ogsa.utils.GridServiceFactory;
import org.gridforum.ogsi.ExtensibilityType;
import org.gridforum.ogsi.Factory;
import org.gridforum.ogsi.GridService;
import org.gridforum.ogsi.HandleType;
import org.gridforum.ogsi.LocatorType;
import org.gridforum.ogsi.OGSIServiceGridLocator;

public class FileStreamTestCase extends TestCase {
    private static final String FSFF_BASE_PATH
        = "base/streaming/FileStreamFactoryFactoryService";
    private static final String FSF_INSTANCE_ID = "testFileStreamFactory";
    private static final String FSS_INSTANCE_ID = "testFileStream";

    private static final String TEST_SOURCE_FILE
        = "test-reports/test_fss_source_file";
    private static final String TEST_DESTINATION_FILE
        = "test-reports/test_fss_source_file";
    private static final String TEST_DESTINATION_URL
        = "file:///"
        + System.getProperty("user.dir")
        + "/"
        + TEST_DESTINATION_FILE;
    private static final String[] TEST_PATTERNS
        = {"~~~~!!!!@@@@####$$$$%%%%^^^^&&&&****(((())))____++++",
           "~!@#$%^&*()_++_)(*&^%$#@!~~!@#$%^&*()_++_)(*&^%$#@!~"};

    private static TestServer testServer;

    private static HandleType fileStreamFactoryHandle = null;

    private static OGSIServiceGridLocator gridServiceLocator
        = new OGSIServiceGridLocator();

    public FileStreamTestCase(String name) {
        super(name);
    }

    public static void setTestServer(TestServer testServer) {
        FileStreamTestCase.testServer = testServer;
    }

    public static Test suite() {
        return new TestSuite(FileStreamTestCase.class);
    }

    protected void setUp() throws Exception {
        //create a file stream factory
        System.out.println(   "Test Server Base URL: "
                            + FileStreamTestCase.testServer.getBaseURL());
        /*
        String serviceFactoryUrl
            = FileStreamTestCase.testServer.getBaseURL()
            + FSFF_BASE_PATH;
            */
        String serviceFactoryUrl
            = "http://127.0.0.1:8080/ogsa/services/"
            + FSFF_BASE_PATH;

        GridServiceFactory fileStreamFactoryFactory = null;
        try {
            fileStreamFactoryFactory = new GridServiceFactory(
                    this.gridServiceLocator.getFactoryPort(
                        new URL(serviceFactoryUrl)));
        } catch (MalformedURLException murle) {
            System.err.println("ERROR: failed to locate factory -- ");
            System.err.println(murle.getMessage());
            murle.printStackTrace();
        }

        FileStreamFactoryAttributesWrapper factoryAttributesWrapper
            = new FileStreamFactoryAttributesWrapper();
        FileStreamFactoryAttributes factoryAttributes
            = new FileStreamFactoryAttributes();
        factoryAttributes.setSourcePath(TEST_SOURCE_FILE);
        factoryAttributesWrapper.setFileStreamFactoryAttributes(
                    factoryAttributes);
        ExtensibilityType creationParameters
            = AnyHelper.getExtensibility(factoryAttributesWrapper);

        LocatorType factoryHandleLocator
            = fileStreamFactoryFactory.createService(
                    null, FSF_INSTANCE_ID, creationParameters);

        this.fileStreamFactoryHandle = factoryHandleLocator.getHandle(0);
    }

    protected void tearDown() throws Exception {
        //destroy the file stream factory
        GridService fileStreamFactory = this.gridServiceLocator.getFactoryPort(
                    this.fileStreamFactoryHandle);
        fileStreamFactory.destroy();
    }

    private FileStreamPortType createFileStream() throws RemoteException  {
        GridServiceFactory fileStreamFactory = new GridServiceFactory(
                this.gridServiceLocator.getFactoryPort(
                    this.fileStreamFactoryHandle));

        FileStreamAttributesWrapper fileStreamAttributesWrapper
            = new FileStreamAttributesWrapper();
        FileStreamAttributes fileStreamAttributes = new FileStreamAttributes();
        fileStreamAttributes.setDestinationUrl(TEST_DESTINATION_URL);
        fileStreamAttributes.setOffset(0);
        fileStreamAttributesWrapper.setFileStreamAttributes(
                fileStreamAttributes);
        ExtensibilityType creationParameters
            = AnyHelper.getExtensibility(fileStreamAttributesWrapper);

        LocatorType fileStreamHandleLocator
            = fileStreamFactory.createService(
                    null, FSS_INSTANCE_ID, creationParameters);

        HandleType fileStreamHandle = fileStreamHandleLocator.getHandle(0);

        FileStreamServiceGridLocator fileStreamLocator
            = new FileStreamServiceGridLocator();
        FileStreamPortType fileStream = fileStreamLocator.getFileStreamPort(
                            fileStreamHandle);

        return fileStream;
    }

    private void sendTestPattern(int testPatternIndex) {
        try {
            BufferedWriter writer = new BufferedWriter(
                    new FileWriter(TEST_SOURCE_FILE));
            writer.write(TEST_PATTERNS[testPatternIndex]);
            writer.close();
        } catch (IOException ioe) {
            System.err.println("ERROR: source file write failed -- ");
            System.err.println(ioe.getMessage());
            ioe.printStackTrace();
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
            System.err.println("ERROR: destination file read failed -- ");
            System.err.println(ioe.getMessage());
            ioe.printStackTrace();
        }
    }

    public void testStream() {
        FileStreamPortType fileStream = null;

       ((Stub) fileStream)._setProperty(Constants.MSG_SEC_TYPE,
                                        Constants.SIGNATURE);
       ((Stub) fileStream)._setProperty(GSIConstants.GSI_AUTHORIZATION,
                                        SelfAuthorization.getInstance());

        try {
            fileStream = createFileStream();
            assertTrue(true);
        } catch (RemoteException re) {
            System.err.println("ERROR: file stream creation failed -- ");
            System.err.println(re.getMessage());
            re.printStackTrace();
            assertTrue(false);
        }

        sendTestPattern(0);

        try {
            fileStream.start();
            assertTrue(true);
        } catch (RemoteException re) {
            System.err.println("ERROR: file stream start failed -- ");
            System.err.println(re.getMessage());
            re.printStackTrace();
            assertTrue(false);
        }

        assertTestPatternTransmitted(0);

        sendTestPattern(1);
        try {
            Thread.currentThread().sleep(1000);
        } catch (InterruptedException ie) {
            System.err.println("sleep interrupted");
        }
        assertTestPatternTransmitted(1);

        try {
            fileStream.stop();
            assertTrue(true);
        } catch (RemoteException re) {
            System.err.println("ERROR: file stream stop failed -- ");
            System.err.println(re.getMessage());
            re.printStackTrace();
            assertTrue(false);
        }

        try {
            fileStream.destroy();
            assertTrue(true);
        } catch (RemoteException re) {
            System.err.println("ERROR: file stream destruction failed -- ");
            System.err.println(re.getMessage());
            re.printStackTrace();
            assertTrue(false);
        }
    }

    public static void main(String[] args) {
        TestRunner.run(suite());
    }
}
