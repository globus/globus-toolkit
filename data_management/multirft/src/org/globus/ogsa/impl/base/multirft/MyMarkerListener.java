package org.globus.ogsa.impl.base.multirft;

import java.rmi.RemoteException;

import java.util.StringTokenizer;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import org.globus.ftp.ByteRangeList;
import org.globus.ftp.GridFTPRestartMarker;
import org.globus.ftp.Marker;
import org.globus.ftp.MarkerListener;
import org.globus.ftp.PerfMarker;
import org.globus.ftp.exception.PerfMarkerException;

import org.globus.ogsa.ServiceData;
import org.globus.ogsa.ServiceDataSet;
import org.globus.ogsa.base.multirft.FileTransferProgressType;
import org.globus.ogsa.base.multirft.FileTransferRestartMarker;
import org.globus.ogsa.base.multirft.GridFTPPerfMarkerElement;
import org.globus.ogsa.base.multirft.GridFTPPerfMarkerType;
import org.globus.ogsa.base.multirft.GridFTPRestartMarkerElement;
import org.globus.ogsa.base.multirft.GridFTPRestartMarkerType;
import org.globus.ogsa.config.ContainerConfig;
import org.globus.ogsa.impl.base.multirft.TransferDbAdapter;
import org.globus.ogsa.impl.base.multirft.TransferDbOptions;
import org.globus.ogsa.utils.AnyHelper;

import org.gridforum.ogsi.ServiceDataType;


public class MyMarkerListener
    implements MarkerListener {

    public ByteRangeList list;
    TransferDbAdapter dbAdapter;
    int transferid;
    private static Logger logger = Logger.getLogger(MyMarkerListener.class.getName());
    FileTransferProgressType transferProgress;
    ServiceDataSet serviceData;
    ServiceData transferProgressData;
    FileTransferRestartMarker restartMarkerType;
    ServiceData restartMarkerServiceDataType;
    ServiceData gridFTPRestartMarkerSD;
    GridFTPRestartMarkerElement gridFTPRestartMarkerElement;
    ServiceData gridFTPPerfMarkerSD;
    GridFTPPerfMarkerElement gridFTPPerfMarkerElement;
    long size;

    public MyMarkerListener(TransferDbOptions dbOptions, 
                            FileTransferProgressType transferProgress, 
                            ServiceDataSet serviceData, 
                            ServiceData transferProgressData, long size, 
                            ServiceData restartMarkerServiceDataType, 
                            FileTransferRestartMarker restartMarkerType, 
                            ServiceData gridFTPRestartMarkerSD, 
                            GridFTPRestartMarkerElement gridFTPRestartMarkerElement, 
                            ServiceData gridFTPPerfMarkerSD, 
                            GridFTPPerfMarkerElement gridFTPPerfMarkerElement) {

        try {
            dbAdapter = new TransferDbAdapter(dbOptions);
            list = new ByteRangeList();
            this.transferProgress = transferProgress;
            this.serviceData = serviceData;
            this.transferProgressData = transferProgressData;
            this.size = size;
            this.restartMarkerServiceDataType = restartMarkerServiceDataType;
            this.restartMarkerType = restartMarkerType;
            this.gridFTPRestartMarkerSD = gridFTPRestartMarkerSD;
            this.gridFTPRestartMarkerElement = gridFTPRestartMarkerElement;
            this.gridFTPPerfMarkerSD = gridFTPPerfMarkerSD;
            this.gridFTPPerfMarkerElement = gridFTPPerfMarkerElement;
        } catch (RemoteException re) {
            logger.error("Cannot create DbAdapter" + re.getMessage());
        }
    }

    /**
     * DOCUMENT ME!
     * 
     * @return DOCUMENT ME! 
     */
    public ByteRangeList getByteRangeList() {

        return this.list;
    }

    /**
     * DOCUMENT ME!
     * 
     * @param transferid DOCUMENT ME!
     */
    public void setTransferId(int transferid) {
        this.transferid = transferid;
    }

    /**
     * DOCUMENT ME!
     * 
     * @param m DOCUMENT ME!
     */
    public void markerArrived(Marker m) {

        if (m instanceof GridFTPRestartMarker) {
            restartMarkerArrived((GridFTPRestartMarker)m);
        } else if (m instanceof PerfMarker) {
            perfMarkerArrived((PerfMarker)m);
        } else {
            logger.debug("Unknown format of restart marker");
        }
    }

    /**
     * DOCUMENT ME!
     * 
     * @param marker DOCUMENT ME!
     */
    private void restartMarkerArrived(GridFTPRestartMarker marker) {

        try {
            logger.info("-->restart marker arrived");
            list.merge(marker.toVector());

            String temp = list.toFtpCmdArgument();
            dbAdapter.setRestartMarker(transferid, temp);
            logger.info(
                    "Current transfer state: " + temp + " for transferId: " + 
                    transferid);

            GridFTPRestartMarkerType gridFTPRestartMarkerType = 
                    new GridFTPRestartMarkerType();
            gridFTPRestartMarkerType.setTransferId(this.transferid);
            gridFTPRestartMarkerType.setRestartMarker(temp);
            this.gridFTPRestartMarkerElement.setGridFTPRestartMarker(
                    gridFTPRestartMarkerType);
            this.gridFTPRestartMarkerSD.setValue(gridFTPRestartMarkerElement);
            this.serviceData.add(this.gridFTPRestartMarkerSD);
            this.gridFTPRestartMarkerSD.notifyChange();

            int high = getUpperMarker(temp);
            this.restartMarkerType.setRestartMarkerRange(high);
            restartMarkerServiceDataType.setValue(this.restartMarkerType);
            this.serviceData.add(restartMarkerServiceDataType);
            restartMarkerServiceDataType.notifyChange();
        } catch (Exception e) {
            logger.debug("Exception in MarkerListener" + e.getMessage(), e);
        }
    }

    /**
     * DOCUMENT ME!
     * 
     * @param restartMarker DOCUMENT ME!
     * @return DOCUMENT ME! 
     */
    private int getUpperMarker(String restartMarker) {

        StringTokenizer st = new StringTokenizer(restartMarker, "-");
        String low = st.nextToken();
        String high = st.nextToken();
        int highInt = Integer.parseInt(high);
        double fraction = (double)highInt / this.size;
        fraction = fraction * 100;

        Double doubleFraction = new Double(fraction);
        int integerFraction = doubleFraction.intValue();

        return integerFraction;
    }

    /**
     * DOCUMENT ME!
     * 
     * @param marker DOCUMENT ME!
     */
    private void perfMarkerArrived(PerfMarker marker) {
        logger.info("--> perf marker arrived");

        GridFTPPerfMarkerType gridFTPPerfMarkerType = new GridFTPPerfMarkerType();
        gridFTPPerfMarkerType.setTransferId(this.transferid);

        // time stamp
        logger.info("Timestamp = " + marker.getTimeStamp());
        gridFTPPerfMarkerType.setTimeStamp(marker.getTimeStamp());

        // stripe index
        if (marker.hasStripeIndex()) {

            try {
                logger.info("Stripe index =" + marker.getStripeIndex());
                gridFTPPerfMarkerType.setStripeIndex(marker.getStripeIndex());
            } catch (PerfMarkerException e) {
                logger.debug("Exception in perfMarkerArrived");
            }
        } else {
            logger.info("Stripe index: not present");
        }

        // stripe bytes transferred
        if (marker.hasStripeBytesTransferred()) {

            try {

                long stripeBytesTransferred = marker.getStripeBytesTransferred();
                gridFTPPerfMarkerType.setStripeBytesTransferred(
                        stripeBytesTransferred);
                logger.info(
                        "Stripe bytes transferred = " + 
                        stripeBytesTransferred);

                try {

                    double fraction;

                    if (stripeBytesTransferred == this.size) {
                        fraction = 1;
                    } else {
                        fraction = (double)stripeBytesTransferred / this.size;
                    }

                    fraction = fraction * 100;

                    Double doubleFraction = new Double(fraction);
                    int percentCompleted = doubleFraction.intValue();
                    this.transferProgress.setPercentComplete(percentCompleted);
                    this.transferProgressData.setValue(this.transferProgress);
                    this.serviceData.add(transferProgressData);
                    this.transferProgressData.notifyChange();
                } catch (Exception e) {
                    logger.debug(
                            "Exception while sending Service Data" + 
                            e.getMessage());
                }
            } catch (PerfMarkerException e) {
                logger.debug("Exception in perfMarkerArrived");
            }
        } else {
            logger.info("Stripe Bytes Transferred: not present");
        }

        // total stripe count
        if (marker.hasTotalStripeCount()) {

            try {
                logger.info(
                        "Total stripe count = " + 
                        marker.getTotalStripeCount());
                gridFTPPerfMarkerType.setTotalStripeCount(marker.getTotalStripeCount());
                this.gridFTPPerfMarkerElement.setGridFTPPerfMarker(
                        gridFTPPerfMarkerType);
                this.gridFTPPerfMarkerSD.setValue(gridFTPPerfMarkerElement);
                this.serviceData.add(this.gridFTPPerfMarkerSD);
                this.gridFTPPerfMarkerSD.notifyChange();
            } catch (PerfMarkerException e) {
                logger.debug("Exception in perfMarkerArrived");
            }
             catch (Exception e) {
                logger.debug("Exception in perfMarkerArrived");
            }
        } else {
            logger.info("Total stripe count: not present");
        }
    }
}
