/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
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
import org.globus.ogsa.base.multirft.OverallStatus;
import org.globus.ogsa.base.multirft.TransfersFinished;
import org.globus.ogsa.base.multirft.TransferStatusType;
import org.globus.ogsa.base.multirft.TransfersActive;
import org.globus.ogsa.base.multirft.TransfersPending;
import org.globus.ogsa.base.multirft.TransfersRestarted;
import org.globus.ogsa.base.multirft.TransfersFailed;
import org.globus.ogsa.base.multirft.FileTransferStatusElement;
import org.globus.ogsa.base.multirft.FileTransferJobStatusType;
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

import org.globus.ogsa.client.managers.NotificationSinkManager;
import org.globus.ogsa.NotificationSinkCallback;
import org.globus.ogsa.impl.core.service.ServicePropertiesImpl;
import java.util.HashMap;
import java.util.Set;
import java.util.Iterator;
import java.rmi.RemoteException;
import org.globus.ogsa.wsdl.GSR;
import org.gridforum.ogsi.ServiceDataValuesType;

public class MultiRFTClient 
    extends ServicePropertiesImpl implements NotificationSinkCallback {

    /**
     * DOCUMENT ME!
     * 
     * @param args DOCUMENT ME!
     */

    String[] args;
    NotificationSinkManager nm;
    HashMap requests;
    int transferCount;
    int numDone;
    String sink;
    RFTPortType rftPort;
    
    public MultiRFTClient(String[] args) {
	this.args = args;
	this.requests = new HashMap();
	HashMap map = new HashMap();
	map.put(GSIConstants.GSI_AUTHORIZATION, 
        org.globus.gsi.gssapi.auth.NoAuthorization.getInstance());
	map.put(GSIConstants.GSI_MODE, GSIConstants.GSI_MODE_FULL_DELEG);
	map.put(Constants.GSI_SEC_CONV, Constants.SIGNATURE);
        map.put(Constants.GRIM_POLICY_HANDLER, new IgnoreProxyPolicyHandler());
	nm = NotificationSinkManager.getManager();
	nm.init(map);

	try {
	    nm.startListening(NotificationSinkManager.MAIN_THREAD);
	} catch (Exception e) {
	    System.out.println("NotificationSinkManager could not start listening");
	}
    }
    	
    public void RFTFunc() {
        System.out.println("Multifile RFT command line client");

        GetOpts opts = new GetOpts(
                               "Usage: MultiRFTClient <factory handle> [id] <path to transfer>", 
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

            transferCount = (requestData.size() - 9) / 2;
            TransferType[] transfers1 = new TransferType[transferCount];
            RFTOptionsType multirftOptions = new RFTOptionsType();
            int i=0;
            multirftOptions.setBinary(Boolean.valueOf(
                (String)requestData.elementAt(i++)).booleanValue());
            multirftOptions.setBlockSize(Integer.valueOf(
                (String)requestData.elementAt(i++)).intValue());
            multirftOptions.setTcpBufferSize(Integer.valueOf(
                (String)requestData.elementAt(i++)).intValue());
            multirftOptions.setNotpt(Boolean.valueOf(
                (String)requestData.elementAt(i++)).booleanValue());
            multirftOptions.setParallelStreams(Integer.valueOf(
                (String)requestData.elementAt(i++)).intValue());
            multirftOptions.setDcau(Boolean.valueOf(
                (String)requestData.elementAt(i++)).booleanValue());
            int concurrency = Integer.valueOf(
                (String)requestData.elementAt(i++)).intValue();
            String sourceSubjectName = (String)requestData.elementAt(i++);
            if (sourceSubjectName != null) {
                multirftOptions.setSourceSubjectName(
                    sourceSubjectName);
            }
            String destinationSubjectName = (String)requestData.elementAt(i++);
            if (destinationSubjectName != null) {
                multirftOptions.setDestinationSubjectName(
                    destinationSubjectName);
            } 
            System.out.println(
                    "Number of transfers in this request:"+
                    transferCount);


            for (int j = 0; j < transfers1.length; j++) {
                transfers1[j] = new TransferType();
                transfers1[j].setTransferId(j);
                transfers1[j].setSourceUrl((String)requestData.elementAt(i++));
                transfers1[j].setDestinationUrl(
                        (String)requestData.elementAt(i++));

            }

            TransferRequestType transferRequest = new TransferRequestType();
            transferRequest.setTransferArray(transfers1);
            /*if(concurrency>transfers1.length) {
                System.out.println("Concurrency should be less than the number of transfers in the request");
                System.exit(0);
            }*/

            transferRequest.setRftOptions( multirftOptions );
            transferRequest.setConcurrency( concurrency );

            TransferRequestElement requestElement = new TransferRequestElement();
            requestElement.setTransferRequest(transferRequest);

            ExtensibilityType extension = new ExtensibilityType();
            extension = AnyHelper.getExtensibility(requestElement);

            OGSIServiceGridLocator factoryService = new OGSIServiceGridLocator();
            Factory factory = factoryService.getFactoryPort(new URL(handle));
            GridServiceFactory gridFactory = new GridServiceFactory(factory);

            LocatorType locator = gridFactory.createService(extension);
            System.out.println("Created an instance of Multi-RFT");

    	    GSR reference = GSR.newInstance(locator);
	        sink = nm.addListener("OverallStatus", null, reference.getHandle(), this);


            MultiFileRFTServiceGridLocator loc = new MultiFileRFTServiceGridLocator();
            rftPort = loc.getMultiFileRFTPort(locator);
            ((Stub)rftPort)._setProperty(Constants.AUTHORIZATION, 
                                         NoAuthorization.getInstance());
            ((Stub)rftPort)._setProperty(GSIConstants.GSI_MODE, 
                                         GSIConstants.GSI_MODE_FULL_DELEG);
            ((Stub)rftPort)._setProperty(Constants.GSI_SEC_CONV, 
                                         Constants.SIGNATURE);
            ((Stub)rftPort)._setProperty(Constants.GRIM_POLICY_HANDLER,
                                         new IgnoreProxyPolicyHandler());

            int requestid = rftPort.start();
            System.out.println("Request id: " + requestid);
            System.out.println("Overall Status in form of :");
            System.out.println("Finished:Active:Pending:Restarted:Failed");
	        System.in.read();
	        //printAndExit();

        } catch (Exception e) {
            System.err.println(MessageUtils.toString(e));
        }
    }

    public synchronized void printAndExit() {
	    int finished = 0;
	    int retrying = 0;
	    int failed = 0;
	    int active = 0;
	    int pending = 0;
	    int cancelled = 0;

	    try {
	        nm.removeListener(sink);
	    } catch (Exception e) {
	        System.out.println("Unable to remove listener");
	    }

	    Set keySet = requests.keySet();
	    for (Iterator iter = keySet.iterator(); iter.hasNext(); ) {
	        TransferStatusType status = (TransferStatusType)requests.get((String) iter.next());
	        if (status == TransferStatusType.Finished)
		    finished++;
	        else if (status == TransferStatusType.Retrying)
		    retrying++;
	        else if (status == TransferStatusType.Failed)
		    failed++;
	        else if (status == TransferStatusType.Active)
		    active++;
	        else if (status == TransferStatusType.Pending)
		    pending++;
	        else if (status == TransferStatusType.Cancelled)
		    cancelled++;
	    }
	    System.out.println("Total transfers: " + transferCount);
	    System.out.println("Num finished: " + finished);
	    System.out.println("Num retrying: " + retrying);
	    System.out.println("Num failed: " + failed);
	    System.out.println("Num active: " + active);
	    System.out.println("Num pending: " + pending);
	    System.out.println("Num cancelled: " + cancelled);
	    System.exit(0);
   }
    
    public void deliverNotification(ExtensibilityType ext) throws RemoteException {
    	
        ServiceDataValuesType serviceData = (ServiceDataValuesType)
            AnyHelper.getAsServiceDataValues(ext);
	    OverallStatus overallStatus = (OverallStatus)
            AnyHelper.getAsSingleObject(serviceData, OverallStatus.class);
	    TransfersFinished transfersFinished = overallStatus.getTransfersFinished();
            TransfersActive transfersActive = overallStatus.getTransfersActive();
            TransfersPending transfersPending = overallStatus.getTransfersPending();
            TransfersRestarted transfersRestarted = overallStatus.getTransfersRestarted();
            TransfersFailed transfersFailed = overallStatus.getTransfersFailed();
            synchronized(requests) {
	    //    requests.put(destination, status);
            
            System.out.println(transfersFinished.getNumberFinished() + ":"+
                transfersActive.getNumberActive()+":"+transfersPending.getNumberPending() +
                ":"+transfersRestarted.getNumberRestarted()+
                ":"+ transfersFailed.getNumberFailed());
            
	        /*if (transfersFinished.getNumberFinished() !=0 ){
		    numDone++;
                    
	        }*/
	    }
	    if (transfersFinished.getNumberFinished() == transferCount) {
	       System.out.println("Done");
           try {
	           // nm.removeListener(sink);
               // rftPort.destroy();
	        } catch (Exception e) {
	            System.out.println("Unable to remove listener");
                e.printStackTrace();
	        }

                // printAndExit();
	    }
    }

    public static void main(String[] args) {
    	MultiRFTClient client = new MultiRFTClient(args);
	    client.RFTFunc();
    }
}
