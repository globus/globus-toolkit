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

import java.net.URL;
import java.net.MalformedURLException;
import java.rmi.RemoteException;

import org.apache.log4j.Logger;

import org.globus.ftp.ByteRangeList;
import org.globus.ftp.GridFTPClient;
import org.globus.ftp.GridFTPRestartMarker;
import org.globus.ftp.GridFTPSession;
import org.globus.ftp.RetrieveOptions;
import org.globus.util.GlobusURL;

import org.globus.ogsa.impl.base.reliabletransfer.MyMarkerListener;
import org.globus.ogsa.impl.base.reliabletransfer.TransferDbOptions;
import org.globus.ogsa.base.reliabletransfer.FileTransferProgressType;
import org.globus.ogsa.base.reliabletransfer.FileTransferRestartMarker;
import org.globus.ogsa.utils.MessageUtils;
import org.globus.ogsa.ServiceDataSet;
import org.globus.ogsa.ServiceData;

import org.gridforum.ogsa.ServiceDataType;

import org.gridforum.jgss.ExtendedGSSManager;
import org.gridforum.jgss.ExtendedGSSCredential;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

public class TransferClient {
    GridFTPClient sourceHost;
    GridFTPClient destinationHost;
    String sourcePath;
    String destinationPath;
    String proxyPath;
    String sourceHostName;
    String destinationHostName;
    int status;
    int transferid;
    int parallelism;
    int tcpBufferSize;
    int sourcePort;
    int destinationPort;
    GSSCredential credential;
    MyMarkerListener markerListener;
    GlobusURL sourceGlobusURL;
    GlobusURL destinationGlobusURL;
    long size;
    private static Logger logger = Logger.getLogger (TransferClient.class.getName ());

    public TransferClient(int transferid,
                          String sourceURL,
                          String destinationURL,
                          String proxyPath,
                          TransferDbOptions dbOptions,
                          FileTransferProgressType transferProgress,
                          ServiceDataSet serviceData,
                          ServiceData transferProgressData,
                          ServiceData restartMarkerServiceData,
                          FileTransferRestartMarker restartMarker) throws RemoteException {
        try {
            this.transferid = transferid;
            sourceGlobusURL = new GlobusURL(sourceURL);
            destinationGlobusURL = new GlobusURL(destinationURL);
            sourceHostName = sourceGlobusURL.getHost ();
            destinationHostName = destinationGlobusURL.getHost ();
            sourcePath = "/" + sourceGlobusURL.getPath ();
            destinationPath = "/" + destinationGlobusURL.getPath ();
            sourcePort = sourceGlobusURL.getPort ();
            destinationPort = destinationGlobusURL.getPort ();
            sourceHost = new GridFTPClient(sourceGlobusURL.getHost (),
                                           sourceGlobusURL.getPort ());
            destinationHost = new GridFTPClient(destinationGlobusURL.getHost (),
                                                destinationGlobusURL.getPort ());

	    this.credential = loadCredential(proxyPath);
            setTransferParams ( destinationHost, this.credential );
            setTransferParams ( sourceHost, this.credential );

            size = sourceHost.getSize(sourcePath);
            markerListener = new MyMarkerListener(dbOptions,transferProgress,
                                                    serviceData,transferProgressData,
                                                    size,restartMarkerServiceData,restartMarker);
            markerListener.setTransferId (transferid);
        }
        catch(MalformedURLException mue) {
            status = 2;
            logger.error ("Error in TransferClient:Invalid URLs", mue);
        }
	catch(Exception e) {
            status = 2;
	    logger.error ("Error in TransferClient:Invalid URLs", e);
            throw new RemoteException(MessageUtils.toString(e));
        }
    }

    public static GSSCredential loadCredential(String credPath) 
	throws GSSException {
	ExtendedGSSManager manager = 
	    (ExtendedGSSManager)ExtendedGSSManager.getInstance();
	String handle = "X509_USER_PROXY=" + credPath;
	return manager.createCredential(handle.getBytes(),
					ExtendedGSSCredential.IMPEXP_MECH_SPECIFIC,
					GSSCredential.DEFAULT_LIFETIME,
					null,
					GSSCredential.INITIATE_AND_ACCEPT);
    }

    public static String saveCredential(GSSCredential credential) 
	throws GSSException {
	if (!(credential instanceof ExtendedGSSCredential)) {
	    throw new GSSException(GSSException.FAILURE);
	}
	ExtendedGSSManager manager = 
	    (ExtendedGSSManager)ExtendedGSSManager.getInstance();
	byte [] buf = 
	    ((ExtendedGSSCredential)credential).export(ExtendedGSSCredential.IMPEXP_MECH_SPECIFIC);
	if (buf == null) {
	    throw new GSSException(GSSException.FAILURE);
	}
	String handle = new String(buf);
	int pos = handle.indexOf('=');
	if (pos == -1) {
	    throw new GSSException(GSSException.FAILURE);
	}
	return handle.substring(pos+1).trim();
    }

    public void setProxyPath(String proxyPath) {
        this.proxyPath = proxyPath;
    }

    public void setSource(GridFTPClient host) {
        this.sourceHost = host;
    }

    public GridFTPClient getSource() {

        return this.sourceHost;
    }

    public int getStatus() {

        return this.status;
    }

    public void setDestination(GridFTPClient destinationHost) {
        this.destinationHost = destinationHost;
    }

    public GridFTPClient getDestination() {

        return this.destinationHost;
    }

    public void setDestinationPath(String destPath) {
        this.destinationPath = destPath;
    }

    public int getTransferID() {

        return this.transferid;
    }

    public String getDestinationPath() {

        return destinationPath;
    }

    public void setSourcePath(String sourcePath) {
        this.sourcePath = sourcePath;
    }

    public String getSourcePath() {

        return this.sourcePath;
    }

    public void setTransferParams(GridFTPClient host,
                                  GSSCredential cred) {
        try {
            host.authenticate (cred);
            host.setProtectionBufferSize (16384);
            host.setType (GridFTPSession.TYPE_IMAGE);
            host.setMode (GridFTPSession.MODE_EBLOCK);
        }
	catch(Exception e) {
            logger.debug ("Error in setting Params", e);
            status = 2;
            return;
        }
    }

    public void setRestartMarker(String marker) {
        try {
            marker = "Range Marker " + marker;
            GridFTPRestartMarker restartmarker = new GridFTPRestartMarker(
                                                         marker);
            ByteRangeList list = new ByteRangeList();
            list.merge (restartmarker.toVector ());
            this.sourceHost.setRestartMarker (list);
        }
	catch(Exception e) {
	    logger.error ("Error in setting the restart marker", e);
	}
    }

    public void setParallelStreams(int parallel) {
        this.parallelism = parallel;
    }

    public void setTcpBufferSize(int tcpBufferSize) {
        this.tcpBufferSize = tcpBufferSize;
    }

    public void transfer() {
        try {
            sourceHost.setOptions (new RetrieveOptions(parallelism));
            sourceHost.setTCPBufferSize(this.tcpBufferSize);
            destinationHost.setTCPBufferSize(this.tcpBufferSize);
            sourceHost.extendedTransfer (this.sourcePath,
                                         this.destinationHost,
                                         this.destinationPath,
                                         markerListener);
            status = 0;
        }
	catch(Exception e) {
            logger.debug ("Exception in transfer", e);
            if(status != 2) {
                status = 1;
            }
        }
    }

    public static void main(String[] as) {
    }
}

