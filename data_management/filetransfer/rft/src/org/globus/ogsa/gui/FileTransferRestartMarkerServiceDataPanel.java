package org.globus.ogsa.gui;

import javax.swing.JLabel;
import javax.swing.JProgressBar;
import java.awt.FlowLayout;
import javax.swing.Timer;
import javax.swing.JOptionPane;
import java.net.URL;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.util.Map;
import java.util.Hashtable;
import java.rmi.RemoteException;
import java.net.URL;


import org.globus.ogsa.utils.AnyHelper;
import org.globus.ogsa.impl.core.service.QueryHelper;
import org.globus.ogsa.impl.core.notification.NotificationSinkManager;
import org.globus.ogsa.impl.core.notification.NotificationSinkCallback;
import org.globus.ogsa.base.reliabletransfer.FileTransferRestartMarker;
import org.gridforum.ogsa.GridServicePortType;
import org.gridforum.ogsa.GridServiceGridLocator;
import org.gridforum.ogsa.ServiceDataType;
import org.gridforum.ogsa.ExtensibilityType;
import org.globus.ogsa.utils.GSIUtils;


import org.w3c.dom.Element;

import org.apache.axis.utils.XMLUtils;

import javax.xml.rpc.Stub;
import javax.xml.namespace.QName;

import com.ibm.wsdl.util.xml.DOM2Writer;

import java.util.Hashtable;
import java.rmi.RemoteException;

import org.globus.axis.transport.GSIHTTPTransport;
import org.globus.gsi.gssapi.auth.SelfAuthorization;

public class FileTransferRestartMarkerServiceDataPanel extends AbstractPortTypePanel implements NotificationSinkCallback {
    private Hashtable properties = new Hashtable();
    private NotificationSinkManager manager;
    private String sink;
    private JLabel progressMin;
    private JLabel progressMax;
    private JProgressBar progressBar;

    public FileTransferRestartMarkerServiceDataPanel() {
    super("File Transfer Restart Marker Progress");
    progressMin = new JLabel("0");
    progressMax = new JLabel("100");
    progressBar = new JProgressBar(0,100);
    setLayout(new FlowLayout());
    add(progressMin);
    add(progressBar);
    add(progressMax);
    }

    private void getTransferState() {
    if (this.context == null || this.defaultEndpoint == null) {
	    // TODO: defaultEndpoint error
	    return;
	}

	String wsilDoc = null;
	GridServiceGridLocator fileProgressService = new GridServiceGridLocator();

	try {
	    GridServicePortType fileProgress  = 
		fileProgressService.getGridServicePort(this.defaultEndpoint);
	    
	    GSIUtils.setDefaultGSIProperties( (Stub)fileProgress,
					     this.defaultEndpoint );
	   
            ExtensibilityType queryResult = fileProgress.findServiceData(QueryHelper.getNameQuery(new QName("","FileTransferRestartMarker")));
            ServiceDataType serviceData = (ServiceDataType) AnyHelper.getAny(queryResult);
	        Integer transferState = (Integer) AnyHelper.getAny(serviceData)[0];
	} catch(Exception e) {
	    JOptionPane.showMessageDialog(this, 
					  "Failed to get Transfer Progress: " + 
					  e.getMessage(),
					  "Transfer Service Data: getTransferState error", 
					  JOptionPane.ERROR_MESSAGE);
	    e.printStackTrace();
	    return;
	    }
    }
    
    public void init() {
	getTransferState();

	// for notification: sets authorization type
	setProperty(GSIHTTPTransport.GSI_AUTHORIZATION,
		    SelfAuthorization.getInstance());
	
	// sets gsi mode
	setProperty(GSIHTTPTransport.GSI_MODE,
		    GSIHTTPTransport.GSI_MODE_NO_DELEG);
	
        addTransferProgressListener();
    }

    public void dispose() {
        try {
            if (this.manager.isListening())
            {
                this.manager.removeListener(this.sink);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public void addTransferProgressListener() {
        try {
            // TODO: the right way of doing this is to check weather the defaultEndpoint service
            // supports the Source Service and exposes a RegistryUpdate topic
            this.manager = NotificationSinkManager.getManager();    
            this.manager.startListening();
            this.sink = this.manager.addListener("FileTransferRestartMarker", null, this.handle, this);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
   }
    
   public Object getProperty(String name) {
       return this.properties.get(name);
   } 

   public void setProperty(String name, Object property) {
       this.properties.put(name, property);
   } 

   public void deliverNotification(ExtensibilityType message) throws RemoteException {
        ServiceDataType percentComplete =  (ServiceDataType)(AnyHelper.getAny(message));
        Integer percentCompleted = (Integer)AnyHelper.getAny(percentComplete)[0];
        progressBar.setValue(percentCompleted.intValue());
   }
}

    
    
    
    













