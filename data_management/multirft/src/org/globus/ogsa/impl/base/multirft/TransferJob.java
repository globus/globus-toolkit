/*This file is licensed under the terms of the Globus Toolkit Public|License, found at http://www.globus.org/toolkit/download/license.html.*/
package org.globus.ogsa.impl.base.multirft;

import org.apache.axis.utils.XMLUtils;

import org.globus.ogsa.impl.base.multirft.TransferDbAdapter;
import org.globus.ogsa.impl.base.multirft.RftDBException;

import org.globus.ogsa.base.multirft.TransferType;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.rmi.RemoteException;
/** This class defines a transfer request which is sent to the reliable
 *  transfer server from the control client.  It is also used when the
 *  control client requests a listing of currently executing transfers.
 */
public class TransferJob {

    TransferType transfer;
    int status;
    int attempts;
    TransferDbAdapter dbAdapter;
    public static final int STATUS_FINISHED = 0;
    public static final int STATUS_RETRYING = 1;
    public static final int STATUS_FAILED = 2;
    public static final int STATUS_ACTIVE = 3;
    public static final int STATUS_PENDING = 4;
    public static final int STATUS_CANCELLED = 5;

    static Log logger =
    LogFactory.getLog(TransferJob.class.getName());

    public TransferJob(TransferType transfer, int status, int attempts) { 
        this.transfer = transfer;
        this.status = status;
        this.attempts = attempts;
        this.dbAdapter = TransferDbAdapter.getTransferDbAdapter();
     //   processURLs();
    }

   
    public TransferType getTransfer() {

        return this.transfer;
    }

    public void setTransfer(TransferType transfer) {
        this.transfer = transfer;
    }

    public int getTransferId() {

        return this.transfer.getTransferId();
    }

    public void setTransferId(int transferId) {
        this.transfer.setTransferId(transferId);
    }

    public String getSourceUrl() {

        return this.transfer.getSourceUrl();
    }

    public void setSourceUrl(String sourceUrl) {
        this.transfer.setSourceUrl(sourceUrl);
    }

    public String getDestinationUrl() {

        return this.transfer.getDestinationUrl();
    }

    public void setDestinationUrl(String destinationUrl) {
        this.transfer.setDestinationUrl(destinationUrl);
    }

    public int getStatus() {

        return this.status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public int getAttempts() {

        return this.attempts;
    }

    public void setAttempts(int attempts) {
        this.attempts = attempts;
    }

    public org.globus.ogsa.base.multirft.RFTOptionsType getRftOptions() {

        return this.transfer.getRftOptions();
    }

    public void setRftOptions(org.globus.ogsa.base.multirft.RFTOptionsType rftOptions) {
        this.transfer.setRftOptions(rftOptions);
    }

    public String toString() {

        return new String("From URL: " + transfer.getSourceUrl() + "\n" + 
                          "To URL: " + transfer.getDestinationUrl() + "\n");
    }

    public static Element toElement(int status) {

        Element element = null;

        try {

            Document document = XMLUtils.newDocument();
            element = document.createElement("transferStatus");
            element.setAttribute("status", Integer.toString(status));
            document.appendChild(element);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return element;
    }
}
