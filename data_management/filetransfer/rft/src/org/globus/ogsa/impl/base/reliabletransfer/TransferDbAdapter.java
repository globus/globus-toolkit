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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.rmi.RemoteException;

import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.ogsa.base.reliabletransfer.ReliableTransferOptions;
import org.globus.ogsa.config.ContainerConfig;
import org.globus.ogsa.impl.base.reliabletransfer.TransferDbOptions;
import org.globus.ogsa.utils.MessageUtils;

public class TransferDbAdapter {
    Connection c;

    private static Log logger = 
	LogFactory.getLog ( TransferDbAdapter.class.getName() );

    TransferDbAdapter(TransferDbOptions dbOptions) throws RemoteException{
        try {
            Class.forName (dbOptions.getDriver ());
            c = DriverManager.getConnection (dbOptions.getConnectionURL (),
                                             dbOptions.getUserName (),
                                             dbOptions.getPassword ());
        }
         catch(Exception e) {
            logger.error("Unable to Connect to Database " + e.toString(),e);
            throw new RemoteException(MessageUtils.toString(e));
        }
    }

    public TransferJob getTransferJob(int transferJobId) {
        TransferJob transferJob = null;
        try {
            Statement statement = c.createStatement ();
            ResultSet rs = statement.executeQuery ("select * from transfer where id=" + 
                                                   transferJobId);
            while(rs != null && rs.next ()) {
                int transferJobID = rs.getInt (1);
                String fromURL = rs.getString (2);
                String toURL = rs.getString (3);
                int status = rs.getInt (4);
                int attempts = rs.getInt (5);
                boolean dcau = rs.getBoolean (6);
                int parallelStreams = rs.getInt (7);
                int tcpBufferSize = rs.getInt (8);
                ReliableTransferOptions options = new ReliableTransferOptions();
                options.setParallelStreams (parallelStreams);
                options.setTcpBufferSize (tcpBufferSize);
                options.setDcau (dcau);
                transferJob = new TransferJob(transferJobID,
                                              fromURL,
                                              toURL,
                                              status,
                                              attempts,
                                              options);
            }

            statement.close ();

            return transferJob;
        }
         catch(Exception e) {
	     logger.error("Error", e);
	     return null;
        }
    }

    public int getStatus(int transferJobID) {
        int status = -1;
        try {
            Statement st = c.createStatement ();
            ResultSet rs = st.executeQuery ("SELECT status from transfer " + 
                                            "where id=" + transferJobID);
            while(rs != null && rs.next ()) {
                status = rs.getInt (1);
            }

            st.close ();

            return status;
        }
         catch(Exception e) {
	     logger.error("Error", e);
        }

        return status;
    }

    public Vector getTransfers() {
        Vector transferJobs = new Vector();
        try {
            Statement st = c.createStatement ();
            ResultSet rs = st.executeQuery ("Select * from transfer");
            while(rs != null && rs.next ()) {
                int transferJobID = rs.getInt (1);
                String fromURL = rs.getString (2);
                String toURL = rs.getString (3);
                int status = rs.getInt (4);
                int attempts = rs.getInt (5);
                boolean dcau = rs.getBoolean (6);
                int parallelStreams = rs.getInt (7);
                int tcpBufferSize = rs.getInt (8);
                ReliableTransferOptions options = new ReliableTransferOptions();
                options.setParallelStreams (parallelStreams);
                options.setTcpBufferSize (tcpBufferSize);
                options.setDcau (dcau);
                TransferJob transferJob = new TransferJob(transferJobID,
                                                          fromURL,
                                                          toURL,
                                                          status,
                                                          attempts,
                                                          options);
                transferJobs.add (transferJob);
            }
        }
         catch(Exception e) {
	     logger.error("Error", e);
        }

        return transferJobs;
    }

    public int storeTransferJob(TransferJob transferJob) {
        int transferid = -1;
        try {
            Statement st = c.createStatement ();
            int result = st.executeUpdate ("INSERT into transfer(source_url," + 
                                           "dest_url,status,attempts,dcau,parallel_streams,tcp_buffer_size)" + 
                                           "VALUES('" + 
                                           transferJob.getFromURL () + 
                                           "','" + transferJob.getToURL () + 
                                           "'," + transferJob.getStatus () + 
                                           "," + transferJob.getAttempts () + 
                                           "," + transferJob.getDCAU () + 
                                           "," + 
                                           transferJob.getParallelStreams () + 
                                           "," + 
                                           transferJob.getTCPBufferSize () + 
                                           ")");
            ResultSet rs = st.executeQuery ("SELECT COUNT(id) from transfer");
            while(rs != null && rs.next ()) {
                transferid = rs.getInt (1);
            }

            st.close ();

            return transferid;
        }
	catch(Exception e) {
	    logger.error("Error", e);
            return transferid;
        }
    }

    public void storeProxyLocation(int transferJobID,
                                   String location) {
        try {
            logger.debug ("Storing proxy in: " + location);
            location = location.replace ('\\',
                                         '/');
            Statement st = c.createStatement ();
            int result = st.executeUpdate ("INSERT into proxyinfo(transfer_id," + 
                                           "proxy_loc) VALUES(" + 
                                           transferJobID + ",'" + location + 
                                           "')");
            st.close ();
        }
	catch(Exception e) {
	    logger.error("Error", e);
        }
    }

    public String getProxyLocation(int transferJobID) {
        String proxyLocation = null;
        try {
            Statement st = c.createStatement ();
            ResultSet rs = st.executeQuery ("SELECT proxy_loc from proxyinfo" + 
                                            " where transfer_id=" + 
                                            transferJobID);
            while(rs != null && rs.next ()) {
                proxyLocation = rs.getString (1);
            }
        }
         catch(Exception e) {
	     logger.error("Error", e);
	 }
	
        return proxyLocation;
    }

    public void update(TransferJob transferJob) {
        try {
            Statement st = c.createStatement ();
            int update = st.executeUpdate ("UPDATE transfer SET status= " + 
                                           transferJob.getStatus () + 
                                           ",attempts=" + 
                                           transferJob.getAttempts () + 
                                           ",dcau='" + 
                                           transferJob.getDCAU () + 
                                           "' where id=" + 
                                           transferJob.getTransferJobID ());
            st.close ();
        }
	catch(Exception e) {
	    logger.error("Error", e);
        }
    }

    public String getRestartMarker(int transferJobID) {
        String marker = null;
        try {
            Statement st = c.createStatement ();
            ResultSet rs = st.executeQuery ("Select marker from restart " + 
                                            "where transfer_id=" + 
                                            transferJobID);
            while(rs.next () && rs != null) {
                marker = rs.getString (1);
            }
        }
	catch(Exception e) {
	    logger.error("Error", e);
	}
	
        return marker;
    }

    public void setRestartMarker(int transferJobID,
                                 String marker) {
        try {
            Statement st = c.createStatement ();
            int update = st.executeUpdate ("UPDATE restart set " + 
                                           " marker='" + marker + 
                                           "' where transfer_id=" + 
                                           transferJobID);
            if(update == 0) {
                int insert = st.executeUpdate ("INSERT into restart(transfer_id,marker) " + 
                                               "VALUES(" + transferJobID + 
                                               ",'" + marker + "')");
            }
        }
	catch(Exception e) {
	    logger.error("Error", e);
        }
    }

    public int getActiveTransfers() {
        int activeCount = 0;
        logger.debug ("ActiveCount=" + activeCount);
        try {
            Statement st = c.createStatement ();
            ResultSet rs = st.executeQuery ("SELECT count(id) from transfer " + 
                                            "where status=3");
            logger.debug ("ActiveCount=" + activeCount);
            while(rs != null && rs.next ()) {
                activeCount = rs.getInt (1);
            }
        }
	catch(Exception e) {
	    logger.error("Error", e);
        }

        return activeCount;
    }

    public TransferJob getPendingTransfer() {
        TransferJob transferJob = null;
        try {
            Statement st = c.createStatement ();
            ResultSet rs = st.executeQuery ("Select * from transfer where " + 
                                            " status=4 order by attempts");
            while(rs != null && rs.next ()) {
                int transferJobID = rs.getInt (1);
                String fromURL = rs.getString (2);
                String toURL = rs.getString (3);
                int status = rs.getInt (4);
                int attempts = rs.getInt (5);
                boolean dcau = rs.getBoolean (6);
                int parallelStreams = rs.getInt (7);
                int tcpBufferSize = rs.getInt (8);
                ReliableTransferOptions options = new ReliableTransferOptions();
                options.setParallelStreams (parallelStreams);
                options.setTcpBufferSize (tcpBufferSize);
                options.setDcau (dcau);
                transferJob = new TransferJob(transferJobID,
                                              fromURL,
                                              toURL,
                                              status,
                                              attempts,
                                              options);
            }
        }
	catch(Exception e) {
	    logger.error("Error", e);
        }

        logger.debug (transferJob);

        return transferJob;
    }

    public static void main(String[] as) {
        try {
            String configPath = ContainerConfig.getConfig ().getConfigPath ();
        }
	catch(Exception e) {
            System.err.println (e);
        }
    }
}
