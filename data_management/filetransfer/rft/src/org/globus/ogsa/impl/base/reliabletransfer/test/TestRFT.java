/*
Globus Toolkit Public License (GTPL)

Copyright (c) 1999 University of Chicago and The University of 
Southern California. All Rights Reserved.

 1) The "Software", below, refers to the Globus Toolkit (in either
    source-code, or binary form and accompanying documentation) and a
    "work based on the Software" means a work based on either the
    Software, on part of the Software, or on any derivative work of
    the Software under copyright law: that is, a work containing all
    or a portion of the Software either verbatim or with
    modifications.  Each licensee is addressed as "you" or "Licensee."

 2) The University of Southern California and the University of
    Chicago as Operator of Argonne National Laboratory are copyright
    holders in the Software.  The copyright holders and their third
    party licensors hereby grant Licensee a royalty-free nonexclusive
    license, subject to the limitations stated herein and
    U.S. Government license rights.

 3) A copy or copies of the Software may be given to others, if you
    meet the following conditions:

    a) Copies in source code must include the copyright notice and
       this license.

    b) Copies in binary form must include the copyright notice and
       this license in the documentation and/or other materials
       provided with the copy.

 4) All advertising materials, journal articles and documentation
    mentioning features derived from or use of the Software must
    display the following acknowledgement:

    "This product includes software developed by and/or derived from
    the Globus project (http://www.globus.org/)."

    In the event that the product being advertised includes an intact
    Globus distribution (with copyright and license included) then
    this clause is waived.

 5) You are encouraged to package modifications to the Software
    separately, as patches to the Software.

 6) You may make modifications to the Software, however, if you
    modify a copy or copies of the Software or any portion of it,
    thus forming a work based on the Software, and give a copy or
    copies of such work to others, either in source code or binary
    form, you must meet the following conditions:

    a) The Software must carry prominent notices stating that you
       changed specified portions of the Software.

    b) The Software must display the following acknowledgement:

       "This product includes software developed by and/or derived
        from the Globus Project (http://www.globus.org/) to which the
        U.S. Government retains certain rights."

 7) You may incorporate the Software or a modified version of the
    Software into a commercial product, if you meet the following
    conditions:

    a) The commercial product or accompanying documentation must
       display the following acknowledgment:

       "This product includes software developed by and/or derived
        from the Globus Project (http://www.globus.org/) to which the
        U.S. Government retains a paid-up, nonexclusive, irrevocable
        worldwide license to reproduce, prepare derivative works, and
        perform publicly and display publicly."

    b) The user of the commercial product must be given the following
       notice:

       "[Commercial product] was prepared, in part, as an account of
        work sponsored by an agency of the United States Government.
        Neither the United States, nor the University of Chicago, nor
        University of Southern California, nor any contributors to
        the Globus Project or Globus Toolkit nor any of their employees,
        makes any warranty express or implied, or assumes any legal
        liability or responsibility for the accuracy, completeness, or
        usefulness of any information, apparatus, product, or process
        disclosed, or represents that its use would not infringe
        privately owned rights.

        IN NO EVENT WILL THE UNITED STATES, THE UNIVERSITY OF CHICAGO
        OR THE UNIVERSITY OF SOUTHERN CALIFORNIA OR ANY CONTRIBUTORS
        TO THE GLOBUS PROJECT OR GLOBUS TOOLKIT BE LIABLE FOR ANY
        DAMAGES, INCLUDING DIRECT, INCIDENTAL, SPECIAL, OR CONSEQUENTIAL
        DAMAGES RESULTING FROM EXERCISE OF THIS LICENSE AGREEMENT OR
        THE USE OF THE [COMMERCIAL PRODUCT]."

 8) LICENSEE AGREES THAT THE EXPORT OF GOODS AND/OR TECHNICAL DATA
    FROM THE UNITED STATES MAY REQUIRE SOME FORM OF EXPORT CONTROL
    LICENSE FROM THE U.S. GOVERNMENT AND THAT FAILURE TO OBTAIN SUCH
    EXPORT CONTROL LICENSE MAY RESULT IN CRIMINAL LIABILITY UNDER U.S.
    LAWS.

 9) Portions of the Software resulted from work developed under a
    U.S. Government contract and are subject to the following license:
    the Government is granted for itself and others acting on its
    behalf a paid-up, nonexclusive, irrevocable worldwide license in
    this computer software to reproduce, prepare derivative works, and
    perform publicly and display publicly.

10) The Software was prepared, in part, as an account of work
    sponsored by an agency of the United States Government.  Neither
    the United States, nor the University of Chicago, nor The
    University of Southern California, nor any contributors to the
    Globus Project or Globus Toolkit, nor any of their employees,
    makes any warranty express or implied, or assumes any legal
    liability or responsibility for the accuracy, completeness, or
    usefulness of any information, apparatus, product, or process
    disclosed, or represents that its use would not infringe privately
    owned rights.

11) IN NO EVENT WILL THE UNITED STATES, THE UNIVERSITY OF CHICAGO OR
    THE UNIVERSITY OF SOUTHERN CALIFORNIA OR ANY CONTRIBUTORS TO THE
    GLOBUS PROJECT OR GLOBUS TOOLKIT BE LIABLE FOR ANY DAMAGES,
    INCLUDING DIRECT, INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES
    RESULTING FROM EXERCISE OF THIS LICENSE AGREEMENT OR THE USE OF
    THE SOFTWARE.
*/
package org.globus.ogsa.impl.base.reliabletransfer.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.globus.ogsa.base.reliabletransfer.ReliableFileTransferServiceGridLocator;
import org.globus.ogsa.base.reliabletransfer.ReliableTransferPortType;
import org.globus.ogsa.base.reliabletransfer.ReliableTransferOptions;
import org.globus.ogsa.base.reliabletransfer.ReliableTransferAttributes;

import org.gridforum.ogsa.FactoryServiceGridLocator;
import org.gridforum.ogsa.GridServiceGridLocator;
import org.gridforum.ogsa.GridServicePortType;
import org.gridforum.ogsa.FactoryPortType;

import org.gridforum.ogsa.ServiceTerminationReferenceType;
import org.gridforum.ogsa.CreationType;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.rmi.RemoteException;
import org.globus.gsi.gssapi.auth.NoAuthorization;
import org.globus.ogsa.impl.security.authentication.Constants;
import org.globus.axis.gsi.GSIConstants;
import org.apache.axis.utils.XMLUtils;
import javax.xml.rpc.Stub;
import java.net.URL;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileInputStream;
import java.util.Properties;

/**
 * tests RFT base service
 */
public class TestRFT extends TestCase {

    static Log logger =
              LogFactory.getLog(TestRFT.class.getName());

    public TestRFT(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(TestRFT.class);
    }

    public void testRFTService() throws Exception {
	String propFileName = System.getProperty("intTestPropertyFile");
	Properties prop = new Properties();
	prop.load(new FileInputStream(propFileName));
	String rftFactory = prop.getProperty("rftFactoryEndpoint");
	String rftTCPBuffer = prop.getProperty("tcpBuffer");
	String rftTCPStream = prop.getProperty("streams");

	String rftSrcFile = System.getProperty("rftSrcFile");
	String rftDestFile = System.getProperty("rftDestFile");
	String serviceMachine = System.getProperty("testServiceMachine");
	String servicePort = System.getProperty("testServicePort");
	String rftSrcURL = System.getProperty("rftSrcMachine");
	String rftDestURL = System.getProperty("rftDestMachine");
	String verifyTrue = System.getProperty("verifyTrue");

	String pathSeparator = System.getProperty("file.separator");

	if (rftSrcFile.startsWith(pathSeparator))
	    rftSrcFile = rftSrcFile.substring(1, rftSrcFile.length());
	if (rftDestFile.startsWith(pathSeparator))
	    rftDestFile = rftDestFile.substring(1, rftDestFile.length());
	
	rftClient("http://" + serviceMachine + ":" + servicePort + "/"
		  + rftFactory, rftSrcURL + "/" + rftSrcFile , rftDestURL 
		  + "/" + rftDestFile, rftTCPBuffer, rftTCPStream );

	Thread.currentThread().sleep(10);
	if ( (verifyTrue.equals("true")) || (verifyTrue.equals("yes")))
	    verifyOutput("/" + rftSrcFile, "/" + rftDestFile);
    }

    private static void rftClient(String factoryEndpoint, String srcURL, String destURL, String tcpBuffer, String parallelStreams ) 
	throws Exception {

	logger.debug("rftClient called");
	FactoryServiceGridLocator factoryService = new FactoryServiceGridLocator();
	FactoryPortType factory = factoryService.getFactoryPort(new URL(factoryEndpoint));
	CreationType creation = new CreationType();
	((Stub)factory)._setProperty(GSIConstants.GSI_AUTHORIZATION, NoAuthorization.getInstance());
	((Stub)factory)._setProperty(GSIConstants.GSI_MODE, GSIConstants.GSI_MODE_FULL_DELEG);
	((Stub)factory)._setProperty(Constants.MSG_SEC_TYPE, Constants.SIGNATURE);
	
	ServiceTerminationReferenceType status = factory.createService(creation);

	ReliableFileTransferServiceGridLocator reliableTransferService = new ReliableFileTransferServiceGridLocator();
	GridServicePortType gridServicePort = reliableTransferService.getGridServicePort(status);
	ReliableTransferPortType rftPortType = reliableTransferService.getReliableTransferPort(status);
	((Stub)rftPortType)._setProperty(GSIConstants.GSI_AUTHORIZATION, NoAuthorization.getInstance());
	((Stub)rftPortType)._setProperty(Constants.MSG_SEC_TYPE, Constants.SIGNATURE);

	ReliableTransferAttributes rftAttributes = new ReliableTransferAttributes();
	ReliableTransferOptions rftOptions = new ReliableTransferOptions();
	rftOptions.setParallelStreams(Integer.parseInt(parallelStreams));
	rftOptions.setTcpBufferSize(Integer.parseInt(tcpBuffer));
	rftAttributes.setReliableTransferOptions(rftOptions);

	int transferJobID  = rftPortType.submitTransferJob( srcURL, destURL, rftAttributes);
    }

    private void verifyOutput(String outputFilename, String templateFilename) 
	throws Exception {
	
	logger.debug("verufy output called with " + outputFilename + " template " + templateFilename);
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
