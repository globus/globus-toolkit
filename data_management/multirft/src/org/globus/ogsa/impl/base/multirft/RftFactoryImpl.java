/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
package org.globus.ogsa.impl.base.multirft;

import java.rmi.RemoteException;

import org.globus.ogsa.FactoryCallback;
import org.globus.ogsa.GridServiceBase;
import org.globus.ogsa.GridServiceException;
import org.globus.ogsa.base.multirft.TransferRequestElement;
import org.globus.ogsa.base.multirft.TransferRequestType;
import org.globus.ogsa.impl.base.multirft.RftImpl;
import org.globus.ogsa.impl.ogsi.FactoryProvider;
import org.globus.ogsa.impl.ogsi.GridServiceImpl;
import org.globus.ogsa.utils.AnyHelper;

import org.gridforum.ogsi.ExtensibilityType;
import org.gridforum.ogsi.holders.ExtensibilityTypeHolder;

public class RftFactoryImpl
    implements FactoryCallback {
    public RftFactoryImpl() {

        // super("Multi File RFT Service");
    }

    /**
     * DOCUMENT ME!
     * 
     * @param base DOCUMENT ME!
     * @throws GridServiceException DOCUMENT ME!
     */
    public void initialize(GridServiceBase base)
                    throws GridServiceException {
    }

    /**
     * DOCUMENT ME!
     * 
     * @param creation DOCUMENT ME!
     * @return DOCUMENT ME! 
     * @throws GridServiceException DOCUMENT ME!
     */
    public GridServiceBase createServiceObject(
            ExtensibilityType                   creation,
            ExtensibilityTypeHolder             extensibilityOutput)
            throws                              GridServiceException {

        RftImpl rftImpl;
        try {

            if (creation.get_any() != null) {
                Object obj = AnyHelper.getAsSingleObject(creation, 
                                                         TransferRequestElement.class);
                if (!(obj instanceof TransferRequestElement)) {
                    throw new GridServiceException("Invalid Service parameter type: " + 
                                                   obj.getClass() + 
                                                   " expected TransferRequestElement");
                }

                TransferRequestElement transferRequestElement = 
                        (TransferRequestElement)obj;
                TransferRequestType transferRequest = transferRequestElement.getTransferRequest();
                rftImpl = new RftImpl(transferRequest);
            } else {
                rftImpl = new RftImpl();
            }
        } catch (RemoteException re) {
            throw new GridServiceException("Error creating RftFactoryImpl", re);
        }

        return rftImpl;
    }
}
