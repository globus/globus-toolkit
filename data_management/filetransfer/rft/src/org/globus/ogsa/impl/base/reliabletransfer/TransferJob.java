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

import org.apache.axis.utils.XMLUtils;

import org.globus.ogsa.base.reliabletransfer.ReliableTransferOptions;

import org.w3c.dom.Document;
import org.w3c.dom.Element;


/** This class defines a transfer request which is sent to the reliable
 *  transfer server from the control client.  It is also used when the
 *  control client requests a listing of currently executing transfers.
 */
public class TransferJob {
    ReliableTransferOptions options;
    int transferJobID;
    String fromURL;
    String toURL;
    boolean DCAU;
    int status;
    int attempts;
    int parallelStreams;
    int tcpBufferSize;
    public static final int STATUS_FINISHED = 0;
    public static final int STATUS_RETRYING = 1;
    public static final int STATUS_FAILED = 2;
    public static final int STATUS_ACTIVE = 3;
    public static final int STATUS_PENDING = 4;
    public static final int STATUS_CANCELLED = 5;

    /** This base constructor is empty and only exists for the JavaBeans
     *  framework.
     */
    public TransferJob() {
        this (-1,null,null,-1,-1,null);
    }

    /** This constructor creates a new transfer request object for use by
     *  the control client and reliable transfer server.
     */
    public TransferJob(int transferJobID,
                       String fromURL,
                       String toURL,
                       boolean DCAU,
                       int status,
                       int attempts,
                       int parallelStreams,
                       int tcpBufferSize) {
        this.transferJobID = transferJobID;
        this.fromURL = fromURL;
        this.toURL = toURL;
        this.DCAU = DCAU;
        this.status = status;
        this.attempts = attempts;
        this.parallelStreams = parallelStreams;
        this.tcpBufferSize = tcpBufferSize;
    }

    public int getTransferJobID() {

        return this.transferJobID;
    }

    public TransferJob(int transferJobID,
                       String fromURL,
                       String toURL,
                       int status,
                       int attempts,
                       ReliableTransferOptions options) {
        this.transferJobID = transferJobID;
        this.fromURL = fromURL;
        this.toURL = toURL;
        this.status = status;
        this.attempts = attempts;
        this.DCAU = options.isDcau ();
        this.tcpBufferSize = options.getTcpBufferSize ();
        this.parallelStreams = (int)options.getParallelStreams ();
    }

    public void setTransferJobID(int transferJobID) {
        this.transferJobID = transferJobID;
    }

    /** Set the URL to transfer from.
     *  @param String fromURL The URL to transfer from
     */
    public void setFromURL(String fromURL) {
        this.fromURL = fromURL;
    }

    /** Get the URL to transfer from.
     *  @return String The URL to transfer from
     */
    public String getFromURL() {

        return fromURL;
    }

    /** Set the URL to transfer to.
     *  @param String toURL The URL to transfer to
     */
    public void setToURL(String toURL) {
        this.toURL = toURL;
    }

    /** Get the URL to transfer to.
     *  @return String The URL to transfer to
     */
    public String getToURL() {

        return toURL;
    }

    /**    Set the DCAU option to
    *    @param boolean DCAU The DCAU Option
    */
    public void setDCAU(boolean DCAU) {
        this.DCAU = DCAU;
    }

    /**    Get the DCAU Option
    *    @return boolean DCAU The DCAU option
    */
    public boolean getDCAU() {

        return DCAU;
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

    public void setTCPBufferSize(int tcpBufferSize) {
        this.tcpBufferSize = tcpBufferSize;
    }

    public int getTCPBufferSize() {

        return this.tcpBufferSize;
    }

    public void setParallelStreams(int parallelStreams) {
        this.parallelStreams = parallelStreams;
    }

    public int getParallelStreams() {

        return this.parallelStreams;
    }

    public String toString() {

        return new String("From URL: " + fromURL + "\n" + "To URL: " + 
                          toURL + "\n" + "DCAU: 	" + DCAU + "\n");
    }

    public static Element toElement(int status) {
        Element element = null;
        try {
            Document document = XMLUtils.newDocument ();
            element = document.createElement ("transferStatus");
            element.setAttribute ("status",
                                  Integer.toString (status));
            document.appendChild (element);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return element;
    }
}
