package org.globus.ogsa.gui;

import org.globus.ogsa.utils.GetOpts;
import org.globus.ogsa.base.multirft.FileTransferJobStatusType;
import org.globus.ogsa.base.multirft.RFTPortType;
import org.globus.ogsa.base.multirft.MultiFileRFTServiceGridLocator;
import org.gridforum.ogsi.GridService;
import org.gridforum.ogsi.HandleType;
import org.gridforum.ogsi.OGSIServiceGridLocator;
import org.globus.axis.gsi.GSIConstants;
import org.globus.gsi.proxy.IgnoreProxyPolicyHandler;
import org.globus.ogsa.impl.security.authorization.NoAuthorization;
import org.globus.ogsa.impl.security.Constants;

import javax.xml.rpc.Stub;
import java.net.URL;

public class GetStatus {
    public static void main( String args[] ) {
        FileTransferJobStatusType status;
        String handle;
        String fileName;
        RFTPortType rftPort;
        GetOpts opts = new GetOpts (
                        "Usage: GetStatus <handle>",2);
        String error = opts.parse(args);
        if( error!=null ) {
            System.err.println(error);
            return;
        }

        handle = opts.getArg(0);
        fileName = opts.getArg(1);
        try {
            OGSIServiceGridLocator locator = new OGSIServiceGridLocator();
            GridService service = 
                    locator.getGridServicePort(new HandleType(handle));
            MultiFileRFTServiceGridLocator loc = new MultiFileRFTServiceGridLocator();
            rftPort = loc.getMultiFileRFTPort(new URL(handle));
            ((Stub)rftPort)._setProperty(Constants.AUTHORIZATION, 
                                         NoAuthorization.getInstance());
            ((Stub)rftPort)._setProperty(GSIConstants.GSI_MODE, 
                                         GSIConstants.GSI_MODE_FULL_DELEG);
            ((Stub)rftPort)._setProperty(Constants.GSI_SEC_CONV, 
                                         Constants.SIGNATURE);
            ((Stub)rftPort)._setProperty(Constants.GRIM_POLICY_HANDLER,
                                         new IgnoreProxyPolicyHandler());
            status = rftPort.getStatus(fileName);
            if(status != null) {
                System.out.println("Transfer Id: " + status.getTransferId());
                System.out.println("Destination: " 
                        + status.getDestinationUrl());
                System.out.println("Status : " + status.getStatus());
            }else {
                System.out.println( "Status is null");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }   
}
