/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
package org.globus.ogsa.impl.base.streaming.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import junit.framework.TestResult;

import org.globus.ogsa.server.test.GridTestSuite;
import org.globus.ogsa.server.test.TestServer;

/**
 * tests ogsified GRAM client
 */
public class PackageTests extends GridTestSuite {

    private TestServer testServer;

    public PackageTests(String name) {
        super(name);
    }

    public static Test suite() throws Exception {
        TestSuite suite = new PackageTests("File Stream Tests");
        suite.addTest(new FileStreamTestCase("testFileStream"));
        return suite;
    }
}
