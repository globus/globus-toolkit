/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
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


/**
 *  Description of the Class
 *
 *@author     madduri
 *@created    October 17, 2003
 */
public class MyMarkerListener
         implements MarkerListener {

    /**
     *  Description of the Field
     */
    public ByteRangeList list;
    TransferDbAdapter dbAdapter;
    int transferid =-1;
    private static Logger logger = Logger.getLogger( MyMarkerListener.class.getName() );
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


    /**
     *  Constructor for the MyMarkerListener object
     */
    public MyMarkerListener() {
        list = new ByteRangeList();
    }


    /**
     *  Constructor for the MyMarkerListener object
     *
     *@param  transferProgress              Description of the Parameter
     *@param  serviceData                   Description of the Parameter
     *@param  transferProgressData          Description of the Parameter
     *@param  size                          Description of the Parameter
     *@param  restartMarkerServiceDataType  Description of the Parameter
     *@param  restartMarkerType             Description of the Parameter
     *@param  gridFTPRestartMarkerSD        Description of the Parameter
     *@param  gridFTPRestartMarkerElement   Description of the Parameter
     *@param  gridFTPPerfMarkerSD           Description of the Parameter
     *@param  gridFTPPerfMarkerElement      Description of the Parameter
     */
    public MyMarkerListener(
            FileTransferProgressType transferProgress,
            ServiceDataSet serviceData,
            ServiceData transferProgressData, long size,
            ServiceData restartMarkerServiceDataType,
            FileTransferRestartMarker restartMarkerType,
            ServiceData gridFTPRestartMarkerSD,
            GridFTPRestartMarkerElement gridFTPRestartMarkerElement,
            ServiceData gridFTPPerfMarkerSD,
            GridFTPPerfMarkerElement gridFTPPerfMarkerElement ) {

        try {
            dbAdapter = TransferDbAdapter.getTransferDbAdapter();
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
        } catch ( Exception re ) {
            logger.error( "Cannot create DbAdapter" + re.getMessage() );
        }
    }


    /**
     *  Sets the transferDbOptions attribute of the MyMarkerListener object
     *
     *@param  dbOptions            The new transferDbOptions value
     *@exception  RemoteException  Description of the Exception
     */
    public void setTransferDbOptions( TransferDbOptions dbOptions )
             throws RemoteException {
        dbAdapter = new TransferDbAdapter( dbOptions );
    }


    /**
     *  Sets the transferProgress attribute of the MyMarkerListener object
     *
     *@param  transferProgress  The new transferProgress value
     */
    public void setTransferProgress( FileTransferProgressType transferProgress ) {
        this.transferProgress = transferProgress;
    }


    /**
     *  Sets the serviceDataSet attribute of the MyMarkerListener object
     *
     *@param  serviceData  The new serviceDataSet value
     */
    public void setServiceDataSet( ServiceDataSet serviceData ) {
        this.serviceData = serviceData;
    }


    /**
     *  Sets the transferProgress attribute of the MyMarkerListener object
     *
     *@param  transferProgressData  The new transferProgress value
     */
    public void setTransferProgress( ServiceData transferProgressData ) {
        this.transferProgressData = transferProgressData;
    }


    /**
     *  Sets the size attribute of the MyMarkerListener object
     *
     *@param  size  The new size value
     */
    public void setSize( long size ) {
        this.size = size;
    }


    /**
     *  Sets the restartMarkerServiceDataType attribute of the MyMarkerListener
     *  object
     *
     *@param  restartMarkerServiceDataType  The new restartMarkerServiceDataType
     *      value
     */
    public void setRestartMarkerServiceDataType( ServiceData restartMarkerServiceDataType ) {
        this.restartMarkerServiceDataType = restartMarkerServiceDataType;
    }


    /**
     *  Sets the fileTransferRestartMarker attribute of the MyMarkerListener
     *  object
     *
     *@param  restartMarkerType  The new fileTransferRestartMarker value
     */
    public void setFileTransferRestartMarker( FileTransferRestartMarker restartMarkerType ) {
        this.restartMarkerType = restartMarkerType;
    }


    /**
     *  Sets the gridFTPRestartMarkerSD attribute of the MyMarkerListener object
     *
     *@param  gridFTPRestartMarkerSD  The new gridFTPRestartMarkerSD value
     */
    public void setGridFTPRestartMarkerSD( ServiceData gridFTPRestartMarkerSD ) {
        this.gridFTPRestartMarkerSD = gridFTPRestartMarkerSD;
    }


    /**
     *  Sets the gridFTPRestartMarkerElement attribute of the MyMarkerListener
     *  object
     *
     *@param  gridFTPRestartMarkerElement  The new gridFTPRestartMarkerElement
     *      value
     */
    public void setGridFTPRestartMarkerElement( GridFTPRestartMarkerElement gridFTPRestartMarkerElement ) {
        this.gridFTPRestartMarkerElement = gridFTPRestartMarkerElement;
    }


    /**
     *  Sets the gridFTPPerfMarkerSD attribute of the MyMarkerListener object
     *
     *@param  gridFTPPerfMarkerSD  The new gridFTPPerfMarkerSD value
     */
    public void setGridFTPPerfMarkerSD( ServiceData gridFTPPerfMarkerSD ) {
        this.gridFTPPerfMarkerSD = gridFTPPerfMarkerSD;
    }


    /**
     *  Sets the gridFTPPerfMarkerElement attribute of the MyMarkerListener
     *  object
     *
     *@param  gridFTPPerfMarkerElement  The new gridFTPPerfMarkerElement value
     */
    public void setGridFTPPerfMarkerElement( GridFTPPerfMarkerElement gridFTPPerfMarkerElement ) {
        this.gridFTPPerfMarkerElement = gridFTPPerfMarkerElement;
    }


    /**
     *  DOCUMENT ME!
     *
     *@return    DOCUMENT ME!
     */
    public ByteRangeList getByteRangeList() {

        return this.list;
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  transferid  DOCUMENT ME!
     */
    public void setTransferId( int transferid ) {
        this.transferid = transferid;
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  m  DOCUMENT ME!
     */
    public void markerArrived( Marker m ) {

        if ( m instanceof GridFTPRestartMarker ) {
            restartMarkerArrived( (GridFTPRestartMarker) m );
        } else if ( m instanceof PerfMarker ) {
            perfMarkerArrived( (PerfMarker) m );
        } else {
            logger.debug( "Unknown format of restart marker" );
        }
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  marker  DOCUMENT ME!
     */
    private void restartMarkerArrived( GridFTPRestartMarker marker ) {

        try {
            logger.info( "-->restart marker arrived" );
            list.merge( marker.toVector() );

            String temp = list.toFtpCmdArgument();
            dbAdapter.setRestartMarker( this.transferid, temp );
            logger.info(
                    "Current transfer state: " + temp + " for transferId: " +
                    this.transferid );

            GridFTPRestartMarkerType gridFTPRestartMarkerType =
                    new GridFTPRestartMarkerType();
            gridFTPRestartMarkerType.setTransferId( this.transferid );
            gridFTPRestartMarkerType.setRestartMarker( temp );
            this.gridFTPRestartMarkerElement.setGridFTPRestartMarker(
                    gridFTPRestartMarkerType );
            this.gridFTPRestartMarkerSD.setValue( gridFTPRestartMarkerElement );
            this.serviceData.add( this.gridFTPRestartMarkerSD );
            this.gridFTPRestartMarkerSD.notifyChange();

            int high = getUpperMarker( temp );
            this.restartMarkerType.setRestartMarkerRange( high );
            restartMarkerServiceDataType.setValue( this.restartMarkerType );
            this.serviceData.add( restartMarkerServiceDataType );
            restartMarkerServiceDataType.notifyChange();
        } catch ( Exception e ) {
            logger.debug( "Exception in MarkerListener" + e.getMessage(), e );
        }
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  restartMarker  DOCUMENT ME!
     *@return                DOCUMENT ME!
     */
    private int getUpperMarker( String restartMarker ) {

        StringTokenizer st = new StringTokenizer( restartMarker, "-" );
        String low = st.nextToken();
        String high = st.nextToken();
        int highInt = Integer.parseInt( high );
        double fraction = (double) highInt / this.size;
        fraction = fraction * 100;

        Double doubleFraction = new Double( fraction );
        int integerFraction = doubleFraction.intValue();

        return integerFraction;
    }


    /**
     *  DOCUMENT ME!
     *
     *@param  marker  DOCUMENT ME!
     */
    private void perfMarkerArrived( PerfMarker marker ) {
        logger.info( "--> perf marker arrived" );

        GridFTPPerfMarkerType gridFTPPerfMarkerType = new GridFTPPerfMarkerType();
        gridFTPPerfMarkerType.setTransferId( this.transferid );

        // time stamp
        logger.info( "Timestamp = " + marker.getTimeStamp() );
        gridFTPPerfMarkerType.setTimeStamp( marker.getTimeStamp() );

        // stripe index
        if ( marker.hasStripeIndex() ) {

            try {
                logger.info( "Stripe index =" + marker.getStripeIndex() );
                gridFTPPerfMarkerType.setStripeIndex( marker.getStripeIndex() );
            } catch ( PerfMarkerException e ) {
                logger.debug( "Exception in perfMarkerArrived" );
            }
        } else {
            logger.info( "Stripe index: not present" );
        }

        // stripe bytes transferred
        if ( marker.hasStripeBytesTransferred() ) {

            try {

                long stripeBytesTransferred = marker.getStripeBytesTransferred();
                gridFTPPerfMarkerType.setStripeBytesTransferred(
                        stripeBytesTransferred );
                logger.info(
                        "Stripe bytes transferred = " +
                        stripeBytesTransferred );

                try {

                    double fraction;

                    if ( stripeBytesTransferred == this.size ) {
                        fraction = 1;
                    } else {
                        fraction = (double) stripeBytesTransferred / this.size;
                    }

                    fraction = fraction * 100;

                    Double doubleFraction = new Double( fraction );
                    int percentCompleted = doubleFraction.intValue();
                    this.transferProgress.setPercentComplete( percentCompleted );
                    this.transferProgressData.setValue( this.transferProgress );
                    this.serviceData.add( transferProgressData );
                    this.transferProgressData.notifyChange();
                } catch ( Exception e ) {
                    logger.debug(
                            "Exception while sending Service Data" +
                            e.getMessage() );
                }
            } catch ( PerfMarkerException e ) {
                logger.debug( "Exception in perfMarkerArrived" +e.getMessage());
            }
        } else {
            logger.info( "Stripe Bytes Transferred: not present" );
        }

        // total stripe count
        if ( marker.hasTotalStripeCount() ) {

            try {
                logger.info(
                        "Total stripe count = " +
                        marker.getTotalStripeCount() );
                gridFTPPerfMarkerType.setTotalStripeCount( marker.getTotalStripeCount() );
                this.gridFTPPerfMarkerElement.setGridFTPPerfMarker(
                        gridFTPPerfMarkerType );
                this.gridFTPPerfMarkerSD.setValue( gridFTPPerfMarkerElement );
                this.serviceData.add( this.gridFTPPerfMarkerSD );
                this.gridFTPPerfMarkerSD.notifyChange();
            } catch ( PerfMarkerException e ) {
                logger.debug( "Exception in perfMarkerArrived" );
            } catch ( Exception e ) {
                logger.debug( "Exception in perfMarkerArrived" );
            }
        } else {
            logger.info( "Total stripe count: not present" );
        }
    }
}

