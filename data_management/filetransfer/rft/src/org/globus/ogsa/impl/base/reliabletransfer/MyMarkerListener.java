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
package org.globus.ogsa.impl.base.reliabletransfer;

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

import org.gridforum.ogsa.ServiceDataType;
import org.globus.ogsa.ServiceDataSet;

import org.globus.ogsa.config.ContainerConfig;
import org.globus.ogsa.utils.AnyHelper;
import org.globus.ogsa.ServiceData;
import org.globus.ogsa.impl.base.reliabletransfer.TransferDbAdapter;
import org.globus.ogsa.impl.base.reliabletransfer.TransferDbOptions;
import org.globus.ogsa.base.reliabletransfer.FileTransferProgressType;
import org.globus.ogsa.base.reliabletransfer.FileTransferRestartMarker;

public class MyMarkerListener
    implements MarkerListener {
    public ByteRangeList list;
    TransferDbAdapter dbAdapter;
    int transferid;
    private static Logger logger = Logger.getLogger (MyMarkerListener.class.getName ());
    FileTransferProgressType transferProgress;
    ServiceDataSet serviceData;
    ServiceData transferProgressData;
    FileTransferRestartMarker restartMarkerType;
    ServiceData restartMarkerServiceDataType;
    long size;

    public MyMarkerListener(TransferDbOptions dbOptions,
                            FileTransferProgressType transferProgress,
                            ServiceDataSet serviceData,
                            ServiceData transferProgressData,
                            long size,ServiceData restartMarkerServiceDataType,
                            FileTransferRestartMarker restartMarkerType) {
        try {
            dbAdapter = new TransferDbAdapter(dbOptions);
            list = new ByteRangeList();
            this.transferProgress = transferProgress;
            this.serviceData = serviceData;
            this.transferProgressData = transferProgressData;
            this.size = size;
            this.restartMarkerServiceDataType = restartMarkerServiceDataType;
            this.restartMarkerType = restartMarkerType;
        } catch (RemoteException re) {
            logger.error("Cannot create DbAdapter" + re.getMessage());
        }
    }

    public ByteRangeList getByteRangeList() {

        return this.list;
    }

    public void setTransferId(int transferid) {
        this.transferid = transferid;
    }

    public void markerArrived(Marker m) {
        if(m instanceof GridFTPRestartMarker) {
            restartMarkerArrived ((GridFTPRestartMarker)m);
        }
         else if(m instanceof PerfMarker) {
            perfMarkerArrived ((PerfMarker)m);
        }
         else {
            logger.debug ("Unknown format of restart marker");
        }
    }


    private void restartMarkerArrived(GridFTPRestartMarker marker) {
        try {
            logger.info ("-->restart marker arrived");
            list.merge (marker.toVector ());
            String temp = list.toFtpCmdArgument();
            dbAdapter.setRestartMarker (transferid,
                                        temp);
            logger.info ("Current transfer state: " + temp);
            int high = getUpperMarker(temp);
            this.restartMarkerType.setRestartMarkerRange(high);
            restartMarkerServiceDataType.setValue(this.restartMarkerType);
            this.serviceData.add(restartMarkerServiceDataType);
            restartMarkerServiceDataType.notifyChange();
        } catch(Exception e) {
            logger.debug("Exception in MarkerListener"+e.getMessage(), e);
        }
    }
    
    private int getUpperMarker(String restartMarker) {
        StringTokenizer st = new StringTokenizer(restartMarker,"-");
        String low = st.nextToken();
        String high = st.nextToken();
        int highInt = Integer.parseInt(high);
        double fraction = (double)highInt/this.size;
        fraction = fraction*100;
        Double doubleFraction = new Double(fraction);
        int integerFraction = doubleFraction.intValue();
        return integerFraction;
    }
    
    private void perfMarkerArrived(PerfMarker marker) {
        logger.info ("--> perf marker arrived");
        // time stamp
        logger.info ("Timestamp = " + marker.getTimeStamp ());
        // stripe index
        if(marker.hasStripeIndex ()) {
            try {
                logger.info ("Stripe index =" + marker.getStripeIndex ());
            }
             catch(PerfMarkerException e) {
                logger.debug ("Exception in perfMarkerArrived");
            }
        }
         else {
            logger.info ("Stripe index: not present");
        }

        // stripe bytes transferred
        if(marker.hasStripeBytesTransferred ()) {
            try {
                long stripeBytesTransferred = marker.getStripeBytesTransferred();
                logger.info ("Stripe bytes transferred = " + 
                             stripeBytesTransferred);
                try {
                       double fraction;
                       if ( stripeBytesTransferred == this.size) {
                            fraction = 1;
                        } else {
                            fraction = (double)stripeBytesTransferred/this.size;
                        }
                            fraction = fraction * 100;
                            Double doubleFraction = new Double(fraction);
                            int percentCompleted = doubleFraction.intValue();
                            this.transferProgress.setPercentComplete(percentCompleted);
                            this.transferProgressData.setValue(this.transferProgress);
                            this.serviceData.add(transferProgressData);
                            this.transferProgressData.notifyChange();

                    } catch (Exception e) {
                    logger.debug("Exception while sending Service Data"+ e.getMessage());
                    }
            }
             catch(PerfMarkerException e) {
                logger.debug ("Exception in perfMarkerArrived");
            }
        }
         else {
            logger.info ("Stripe Bytes Transferred: not present");
        }

        // total stripe count
        if(marker.hasTotalStripeCount ()) {
            try {
                logger.info ("Total stripe count = " + 
                             marker.getTotalStripeCount ());
            }
             catch(PerfMarkerException e) {
                logger.debug ("Exception in perfMarkerArrived");
            }
        }
         else {
            logger.info ("Total stripe count: not present");
        }
    }
}
