/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
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
/**
 * This class defines a transfer request which is sent to the reliable
 *  transfer server from the control client.  It is also used when the
 *  control client requests a listing of currently executing transfers.
 *
 * @author     madduri
 * @created    September 17, 2003
 */
public class TransferJob {

    TransferType transfer;
    int status;
    int attempts;
    TransferDbAdapter dbAdapter;
    /**
     *  Description of the Field
     */
    public final static int STATUS_FINISHED = 0;
    /**
     *  Description of the Field
     */
    public final static int STATUS_RETRYING = 1;
    /**
     *  Description of the Field
     */
    public final static int STATUS_FAILED = 2;
    /**
     *  Description of the Field
     */
    public final static int STATUS_ACTIVE = 3;
    /**
     *  Description of the Field
     */
    public final static int STATUS_PENDING = 4;
    /**
     *  Description of the Field
     */
    public final static int STATUS_CANCELLED = 5;
    
    public final static int STATUS_EXPANDING = 6;

    static Log logger =
            LogFactory.getLog(TransferJob.class.getName());


    /**
     *Constructor for the TransferJob object
     *
     * @param  transfer  Description of the Parameter
     * @param  status    Description of the Parameter
     * @param  attempts  Description of the Parameter
     */
    public TransferJob(TransferType transfer, int status, int attempts) {
        this.transfer = transfer;
        this.status = status;
        this.attempts = attempts;
        this.dbAdapter = TransferDbAdapter.getTransferDbAdapter();
    }


    /**
     *  Gets the transfer attribute of the TransferJob object
     *
     * @return    The transfer value
     */
    public TransferType getTransfer() {

        return this.transfer;
    }


    /**
     *  Sets the transfer attribute of the TransferJob object
     *
     * @param  transfer  The new transfer value
     */
    public void setTransfer(TransferType transfer) {
        this.transfer = transfer;
    }


    /**
     *  Gets the transferId attribute of the TransferJob object
     *
     * @return    The transferId value
     */
    public int getTransferId() {

        return this.transfer.getTransferId();
    }


    /**
     *  Sets the transferId attribute of the TransferJob object
     *
     * @param  transferId  The new transferId value
     */
    public void setTransferId(int transferId) {
        this.transfer.setTransferId(transferId);
    }


    /**
     *  Gets the sourceUrl attribute of the TransferJob object
     *
     * @return    The sourceUrl value
     */
    public String getSourceUrl() {

        return this.transfer.getSourceUrl();
    }


    /**
     *  Sets the sourceUrl attribute of the TransferJob object
     *
     * @param  sourceUrl  The new sourceUrl value
     */
    public void setSourceUrl(String sourceUrl) {
        this.transfer.setSourceUrl(sourceUrl);
    }


    /**
     *  Gets the destinationUrl attribute of the TransferJob object
     *
     * @return    The destinationUrl value
     */
    public String getDestinationUrl() {

        return this.transfer.getDestinationUrl();
    }


    /**
     *  Sets the destinationUrl attribute of the TransferJob object
     *
     * @param  destinationUrl  The new destinationUrl value
     */
    public void setDestinationUrl(String destinationUrl) {
        this.transfer.setDestinationUrl(destinationUrl);
    }


    /**
     *  Gets the status attribute of the TransferJob object
     *
     * @return    The status value
     */
    public int getStatus() {

        return this.status;
    }


    /**
     *  Sets the status attribute of the TransferJob object
     *
     * @param  status  The new status value
     */
    public void setStatus(int status) {
        this.status = status;
    }


    /**
     *  Gets the attempts attribute of the TransferJob object
     *
     * @return    The attempts value
     */
    public int getAttempts() {

        return this.attempts;
    }


    /**
     *  Sets the attempts attribute of the TransferJob object
     *
     * @param  attempts  The new attempts value
     */
    public void setAttempts(int attempts) {
        this.attempts = attempts;
    }


    /**
     *  Gets the rftOptions attribute of the TransferJob object
     *
     * @return    The rftOptions value
     */
    public org.globus.ogsa.base.multirft.RFTOptionsType getRftOptions() {

        return this.transfer.getRftOptions();
    }


    /**
     *  Sets the rftOptions attribute of the TransferJob object
     *
     * @param  rftOptions  The new rftOptions value
     */
    public void setRftOptions(org.globus.ogsa.base.multirft.RFTOptionsType rftOptions) {
        this.transfer.setRftOptions(rftOptions);
    }


    /**
     *  Description of the Method
     *
     * @return    Description of the Return Value
     */
    public String toString() {

        return new String("From URL: " + transfer.getSourceUrl() + "\n" +
                "To URL: " + transfer.getDestinationUrl() + "\n"+ "Id: " 
                +this.getTransferId() );
    }


    /**
     *  Description of the Method
     *
     * @param  status  Description of the Parameter
     * @return         Description of the Return Value
     */
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

