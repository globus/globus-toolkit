/*This file is licensed under the terms of the Globus Toolkit Public|License, found at http://www.globus.org/toolkit/download/license.html.*/
package org.globus.ogsa.gui;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

import java.net.URL;

import java.util.Date;
import java.util.Vector;

import javax.xml.rpc.Stub;

import org.apache.axis.message.MessageElement;
import org.apache.axis.utils.XMLUtils;

import org.globus.axis.gsi.GSIConstants;

import org.globus.ogsa.ServiceProperties;
import org.globus.ogsa.base.multirft.MultiFileRFTServiceGridLocator;
import org.globus.ogsa.base.multirft.RFTOptionsType;
import org.globus.ogsa.base.multirft.RFTPortType;
import org.globus.ogsa.base.multirft.TransferRequestElement;
import org.globus.ogsa.base.multirft.TransferRequestType;
import org.globus.ogsa.base.multirft.TransferType;
import org.globus.ogsa.impl.security.authentication.Constants;
import org.globus.ogsa.impl.security.authorization.NoAuthorization;
import org.globus.ogsa.utils.AnyHelper;
import org.globus.ogsa.utils.GetOpts;
import org.globus.ogsa.utils.GridServiceFactory;
import org.globus.ogsa.utils.MessageUtils;

import org.gridforum.ogsi.ExtendedDateTimeType;
import org.gridforum.ogsi.ExtensibilityNotSupportedFaultType;
import org.gridforum.ogsi.ExtensibilityType;
import org.gridforum.ogsi.ExtensibilityTypeFaultType;
import org.gridforum.ogsi.Factory;
import org.gridforum.ogsi.HandleType;
import org.gridforum.ogsi.InfinityType;
import org.gridforum.ogsi.LocatorType;
import org.gridforum.ogsi.OGSIServiceGridLocator;
import org.gridforum.ogsi.ServiceAlreadyExistsFaultType;
import org.gridforum.ogsi.TerminationTimeType;
import org.gridforum.ogsi.WSDLReferenceType;
import org.gridforum.ogsi.holders.ExtensibilityTypeHolder;
import org.gridforum.ogsi.holders.LocatorTypeHolder;
import org.gridforum.ogsi.holders.TerminationTimeTypeHolder;
import org.globus.gsi.proxy.IgnoreProxyPolicyHandler;

import org.w3c.dom.Document;
import org.w3c.dom.Element;


public class RFTClient {

    /**
     * DOCUMENT ME!
     * 
     * @param args DOCUMENT ME!
     */
    public static void main(String[] args) {
        System.out.println("Multifile RFT command line client");

        GetOpts opts = new GetOpts(
                               "Usage: RFTClient <factory handle> [id] <path to transfer>", 
                               1);
        String error = opts.parse(args);

        if (error != null) {
            System.err.println(error);

            return;
        }

        String handle = opts.getArg(0);

        try {

            File requestFile = new File(opts.getArg(1));
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

            int transferCount = (requestData.size() - 7) / 2;
            TransferType[] transfers1 = new TransferType[transferCount];
            RFTOptionsType multirftOptions = new RFTOptionsType();
            multirftOptions.setBinary(Boolean.valueOf(
                                              (String)requestData.elementAt(0)).booleanValue());
            multirftOptions.setBlockSize(Integer.valueOf(
                                                 (String)requestData.elementAt(
                                                         1)).intValue());
            multirftOptions.setTcpBufferSize(Integer.valueOf(
                                                     (String)requestData.elementAt(
                                                             2)).intValue());
            multirftOptions.setNotpt(Boolean.valueOf(
                                             (String)requestData.elementAt(3)).booleanValue());
            multirftOptions.setParallelStreams(Integer.valueOf(
                                                       (String)requestData.elementAt(
                                                               4)).intValue());
            multirftOptions.setDcau(Boolean.valueOf(
                                            (String)requestData.elementAt(5)).booleanValue());
            System.out.println(
                    "Request Data Size " + requestData.size() + " " + 
                    transferCount);

            int i = 7;

            for (int j = 0; j < transfers1.length; j++) {
                transfers1[j] = new TransferType();
                transfers1[j].setTransferId(j);
                transfers1[j].setSourceUrl((String)requestData.elementAt(i++));
                transfers1[j].setDestinationUrl(
                        (String)requestData.elementAt(i++));
                transfers1[j].setRftOptions(multirftOptions);
            }

            TransferRequestType transferRequest = new TransferRequestType();
            transferRequest.setTransferArray(transfers1);
            int concurrency = Integer.valueOf(
                (String)requestData.elementAt(6)).intValue();
            if(concurrency>transfers1.length) {
                System.out.println("Concurrency should be less than the number of transfers in the request");
                System.exit(0);
            }

            transferRequest.setConcurrency(concurrency);

            TransferRequestElement requestElement = new TransferRequestElement();
            requestElement.setTransferRequest(transferRequest);

            ExtensibilityType extension = new ExtensibilityType();
            extension = AnyHelper.getExtensibility(requestElement);

            OGSIServiceGridLocator factoryService = new OGSIServiceGridLocator();
            Factory factory = factoryService.getFactoryPort(new URL(handle));
            GridServiceFactory gridFactory = new GridServiceFactory(factory);

            /* ((Stub)factory)._setProperty(GSIConstants.GSI_AUTHORIZATION, NoAuthorization.getInstance());
             ((Stub)factory)._setProperty(GSIConstants.GSI_MODE, GSIConstants.GSI_MODE_FULL_DELEG);
             ((Stub)factory)._setProperty(Constants.MSG_SEC_TYPE, Constants.SIGNATURE);*/
            LocatorType locator = gridFactory.createService(extension);
            System.out.println("Created an instance of Multi-RFT");

            MultiFileRFTServiceGridLocator loc = new MultiFileRFTServiceGridLocator();
            RFTPortType rftPort = loc.getMultiFileRFTPort(locator);
            ((Stub)rftPort)._setProperty(Constants.AUTHORIZATION, 
                                         NoAuthorization.getInstance());
            ((Stub)rftPort)._setProperty(GSIConstants.GSI_MODE, 
                                         GSIConstants.GSI_MODE_FULL_DELEG);
            ((Stub)rftPort)._setProperty(Constants.GSI_SEC_CONV, 
                                         Constants.SIGNATURE);
            ((Stub)rftPort)._setProperty(Constants.GRIM_POLICY_HANDLER,
                                                          new IgnoreProxyPolicyHandler());

            /* WSDLReferenceType ref = (WSDLReferenceType) locator.getReference()[0];
             opts.setOptions( ((Stub)factory));
             //AnyHelper.setAny(extension,requestElement);
            //  extension.set_any(any); 
            */
            int requestid = rftPort.start();
            System.out.println("Request id: " + requestid);

            //multirftPortType.cancel(requestid,3,4);
        } catch (Exception e) {
            System.err.println(MessageUtils.toString(e));
        }
    }
}
