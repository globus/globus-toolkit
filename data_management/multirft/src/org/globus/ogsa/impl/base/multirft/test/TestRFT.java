/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
package org.globus.ogsa.impl.base.multirft.test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.Vector;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.ogsa.gui.RFTClient;

/**
 * tests RFT base service
 */
public class TestRFT extends TestCase {

    static Log logger = LogFactory.getLog(TestRFT.class.getName());

    public TestRFT(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(TestRFT.class);
    }

    public void testRFTService() throws Exception {
        String serviceMachine = System.getProperty("testServiceMachine");
        String servicePort = System.getProperty("testServicePort");
        String requestFilename = System.getProperty("rftRequestFile");
        String verifyTrue = System.getProperty("verifyTrue");

        RFTClient.main(new String[]{"http://" + serviceMachine + ":" + servicePort + "/ogsa/services/base/multirft/MultiFileRFTFactoryService", requestFilename});

        Thread.currentThread().sleep(10);

        if ( (verifyTrue.equals("true")) || (verifyTrue.equals("yes")))
            verifyOutput(requestFilename);
    }

    private void verifyOutput(String requestFilename)
        throws Exception {
        
        File requestFile = new File(requestFilename);
        BufferedReader reader = null;
 
        try {
            reader = new BufferedReader(new FileReader(requestFile));
        } catch (java.io.FileNotFoundException fnfe) {
        }

        Vector requestData = new Vector();

        try {
            String line = reader.readLine();

            while (line != null) {
                requestData.add(line);
                line = reader.readLine();
            }
     
            reader.close();
        } catch (java.io.IOException ioe) {
        }
        
        int transferCount = (requestData.size() - 6) / 2;
        int i = 6;
        String srcFilename;
        String destFilename;

        for (int j = 0; j < transferCount; j++) {
            srcFilename = (String)requestData.elementAt(i++);
            destFilename = (String)requestData.elementAt(i++);
            verifyFile("/" + srcFilename, "/" + destFilename);
        }
    }

    private void verifyFile(String templateFilename, String outputFilename)
        throws Exception {

        logger.debug("verify output called with " + outputFilename + " template " + templateFilename);
        BufferedReader outFileReader = new BufferedReader(new FileReader(outputFilename));
        BufferedReader templateFileReader = new BufferedReader(new FileReader(templateFilename));
        String buffer;
        while ((buffer = templateFileReader.readLine()) != null) {
            String outData = outFileReader.readLine();
            System.out.println("Outdata is " + outData);
            assertTrue( (outData != null) && (outData.equals(buffer)));
        }
    }
}
