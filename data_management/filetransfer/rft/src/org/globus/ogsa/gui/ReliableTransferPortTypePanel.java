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
package org.globus.ogsa.gui;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JOptionPane;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JLabel;
import java.net.URL;
import java.util.Map;
import java.util.Hashtable;

import org.globus.ogsa.impl.core.notification.NotificationSinkManager;
import org.globus.ogsa.impl.core.notification.NotificationSinkCallback;
import org.globus.ogsa.impl.core.notification.NotificationSinkCallbackSecureWrapper;
import org.gridforum.ogsa.ExtensibilityType;
import org.globus.ogsa.server.ServiceContainer;
import org.globus.ogsa.base.reliabletransfer.ReliableFileTransferServiceLocator;
import org.globus.ogsa.base.reliabletransfer.ReliableTransferPortType;
import org.globus.ogsa.base.reliabletransfer.ReliableTransferOptions;
import org.globus.ogsa.base.reliabletransfer.ReliableTransferAttributes;

import org.globus.axis.util.Util;
import org.globus.ogsa.utils.GSIUtils;
import org.globus.ogsa.utils.AnyHelper;
import org.globus.ogsa.wsdl.GSR;
import javax.xml.rpc.Stub;

import org.globus.axis.gsi.GSIConstants;
import org.globus.gsi.gssapi.auth.NoAuthorization;
import java.rmi.RemoteException;

import com.ibm.wsdl.util.xml.DOM2Writer;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.apache.axis.utils.XMLUtils;

public class ReliableTransferPortTypePanel extends AbstractPortTypePanel 
    implements NotificationSinkCallback {	

    private JTextField fromURLTF;
    private JTextField toURLTF;
    private JTextField parallelStreamsTF;
    private JTextField tcpBufferSizeTF;
    private JButton statusBT;
    private JButton submitBT;
    private JLabel statusLabel;
    private URL reliableTransferEndpoint;
    private NotificationSinkManager manager;
    private String sink;
    private Hashtable properties = new Hashtable();
    private int transferJobID = -1;

    ReliableFileTransferServiceLocator reliableTransferService;

    public ReliableTransferPortTypePanel() {
	super(" Reliable File Transfer");

	this.reliableTransferService = new ReliableFileTransferServiceLocator();

	submitBT = new JButton("Submit");
    
	submitBT.addActionListener( new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    submitTransferJob();
		}
	    });

	JButton statusBT = new JButton("Update");
	statusBT.addActionListener( new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    getStatus();
		}
	    });

	JPanel setURLPanel = new JPanel();
    JPanel transferOptionsPanel = new JPanel();
    transferOptionsPanel.setLayout(new FlowLayout());
	fromURLTF = new JTextField(20);
	toURLTF = new JTextField(20);
    parallelStreamsTF = new JTextField(20);
    parallelStreamsTF.setText("1");
    tcpBufferSizeTF = new JTextField(20);
    tcpBufferSizeTF.setText("16384");
	setURLPanel.setLayout(new FlowLayout());
    setURLPanel.add(new JLabel("From URL: "));
	setURLPanel.add(fromURLTF);
	setURLPanel.add(new JLabel("To URL: "));
	setURLPanel.add(toURLTF);
	transferOptionsPanel.add(new JLabel("Parallel Streams: "));
	transferOptionsPanel.add(parallelStreamsTF);
	transferOptionsPanel.add(new JLabel("TCP Buffer: "));
	transferOptionsPanel.add(tcpBufferSizeTF);
	JPanel statusPanel = new JPanel();
	statusLabel = new JLabel("Status:NONE");
	statusPanel.add(submitBT);
    statusPanel.add(statusBT);
    statusPanel.add(statusLabel);
	setLayout(new BorderLayout() );
	add(setURLPanel,BorderLayout.NORTH);
    add(transferOptionsPanel,BorderLayout.CENTER);
    add(statusPanel,BorderLayout.SOUTH);
    }
    
    private void submitTransferJob() {
	if (this.context == null || this.handle == null) {
	    return;
	}
	String fromURL = fromURLTF.getText();
	String toURL = toURLTF.getText();
    ReliableTransferAttributes attributes = new ReliableTransferAttributes();
    ReliableTransferOptions options = new ReliableTransferOptions();
    options.setParallelStreams(Integer.parseInt(parallelStreamsTF.getText()));
    options.setTcpBufferSize(Integer.parseInt(tcpBufferSizeTF.getText()));
    attributes.setReliableTransferOptions(options);
	try  {
	    ReliableTransferPortType rftPortType = 
                reliableTransferService.getReliableTransferPort(reliableTransferEndpoint);
	    ((Stub)rftPortType)._setProperty(GSIConstants.GSI_AUTHORIZATION,
					     NoAuthorization.getInstance());

            this.context.setAuthentication((Stub)rftPortType);
	    transferJobID  = rftPortType.submitTransferJob( fromURL, toURL, attributes);
        submitBT.setEnabled(false);
	}
        catch(Exception e) {    
	    JOptionPane.showMessageDialog(this,
					  "Failed to Submit "  +
					  e.getMessage(),
					  "RFT: submit transfer error" ,
					  JOptionPane.ERROR_MESSAGE);
	    e.printStackTrace();
	    return;
	}
    }
		
    public Object getProperty(String name) {
	return properties.get(name);
    }
	
    public void setProperty(String name,Object property)  {
	properties.put(name,property);
    }
    
    public void deliverNotification(ExtensibilityType message) 
	throws RemoteException  {
        try {
	    Element element = AnyHelper.getAnyAsElement(message);
            NodeList list = element.getElementsByTagName("transferStatus");
	    Element status = (Element)list.item(0);
            statusLabel.setText(mapStatus(element.getAttribute("status")));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String mapStatus(String status) {
        if(status.equals("0"))
            return "Finished";
        else if(status.equals("1")) 
            return "Retrying";
        else if(status.equals("2"))
            return "Failed"; 
        else if(status.equals("3"))
            return "Active"; 
        else if(status.equals("4"))
            return "Pending"; 
        else if(status.equals("5"))
            return "Cancelled"; 
        return "None";
    }

    private void getStatus()  {
	    if (this.context == null || this.handle == null) {
	        return;
	}

	try {
	    ReliableTransferPortType rftPortType =
		    reliableTransferService.getReliableTransferPort(reliableTransferEndpoint);
	    this.context.setAuthentication((Stub)rftPortType);
	    ((Stub)rftPortType)._setProperty(GSIConstants.GSI_AUTHORIZATION,
					     NoAuthorization.getInstance());

        int status = rftPortType.getStatus();
        String statusString = "NONE";    
        if(status==0){
            statusString="Finished"; 
            submitBT.setEnabled(true);
        }
        if(status==1)
            statusString="Retrying"; 
        if(status==2)
             statusString="Failed"; 
        if(status==3)
             statusString="Active"; 
        if(status==4)
            statusString="Pending"; 
        if(status==5)
            statusString="Cancelled"; 
        statusLabel.setText(statusString);
	} 
    catch(Exception e) {
	    JOptionPane.showMessageDialog(this,
					  "Failed to get Status" +
					  e.getMessage(),
					  "RFT: get Status  error" ,
					  JOptionPane.ERROR_MESSAGE);
	    e.printStackTrace();
	    return;
	}
    }

    public void init() {
	addGeneratorListener();
	try {
	    reliableTransferEndpoint = new URL(gsr.getEndpoint("ReliableTransferPort"));
	} 
        catch(Exception e) { 
	    e.printStackTrace();
	}	
    }

    public void addGeneratorListener() {
	NotificationSinkCallbackSecureWrapper wrapper =
	    new NotificationSinkCallbackSecureWrapper(this);

	this.manager = NotificationSinkManager.getInstance("Secure");
	try {
	    this.manager.startListening();
	    this.sink = this.manager.addListener("TransferUpdate", null, this.handle, wrapper);
	}
        catch (Exception e) {
	    e.printStackTrace();
	}
    }
    
}
