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
package org.globus.ogsa.impl.base.gram.filestreaming;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.rmi.RemoteException;

import javax.xml.namespace.QName;

import org.globus.ogsa.base.gram.filestreaming.DestinationURLElement;
import org.globus.ogsa.base.gram.filestreaming.FileStreamingOptionsType;
import org.globus.ogsa.base.gram.filestreaming.FileStreamingType;
import org.globus.ogsa.base.gram.filestreaming.FileStreamingPortType;
import org.globus.ogsa.impl.core.factory.SecureFactoryServiceSkeleton;
import org.globus.ogsa.impl.core.service.ServiceSkeleton;
import org.globus.ogsa.impl.core.service.QueryHelper;
import org.globus.ogsa.repository.ServiceNode;
import org.globus.ogsa.GridServiceException;
import org.globus.ogsa.ServiceData;
import org.globus.ogsa.ServiceDataValueCallback;
import org.globus.ogsa.ServiceProperties;
import org.globus.ogsa.ServicePropertiesException;
import org.globus.ogsa.utils.AnyHelper;
import org.globus.gsi.proxy.IgnoreProxyPolicyHandler;

import org.gridforum.ogsa.CreationType;
import org.gridforum.ogsa.ExtensibilityType;
import org.gridforum.ogsa.GridServiceFault;
import org.gridforum.ogsa.HandleType;
import org.gridforum.ogsa.ServiceAlreadyExistsFault;
import org.gridforum.ogsa.ServiceDataType;
import org.gridforum.ogsa.ServiceHandleElementType;
import org.gridforum.ogsa.ServiceTerminationReferenceType;

import java.util.Vector;

public class FileStreamingFactoryImpl extends SecureFactoryServiceSkeleton
        implements ServiceDataValueCallback {
    private static Log logger
        = LogFactory.getLog(FileStreamingFactoryImpl.class);

    static private final String LOCAL_PATH = "localPath";
    private FileStreamingType  fileStreamingAttributes;
    private String localPath;
    protected ExtensibilityType extension;
    private static final String DEST_URLS_SDE_NAME = "DestinationURLs";
    private static final String FILE_STREAMING_HANDLES_SDE_NAME
            = "FileStreamingHandles";
    private static final QName FILE_STREAMING_HANDLES_SDE_QNAME
            = new QName(FILE_STREAMING_HANDLES_SDE_NAME); 
    private ServiceData fileStreamingHandles;

    public FileStreamingFactoryImpl() {
        super ("File Streaming Factory Service");

        this.localPath = (String) getPersistentProperty(LOCAL_PATH);
        this.secContextSkeleton.setGrimPolicyHandler(
                new IgnoreProxyPolicyHandler());
    }

    public FileStreamingFactoryImpl(FileStreamingType fileStreamingAttributes)
            throws RemoteException {
        super ("File Streaming Factory Service");
        this.secContextSkeleton.setGrimPolicyHandler(
                new IgnoreProxyPolicyHandler());

        this.localPath = fileStreamingAttributes.getPath();
        this.fileStreamingAttributes = fileStreamingAttributes;
        fileStreamingHandles = this.serviceData.create(
                FILE_STREAMING_HANDLES_SDE_NAME);
        fileStreamingHandles.setCallback(this);
        this.serviceData.add(fileStreamingHandles);

        try {
            setPersistentProperty(LOCAL_PATH, this.localPath);
            flush();
        } catch (ServicePropertiesException spe) {
            throw new RemoteException("Error storing persistent properties",
                    spe);
        }
    }

    private String[] getDestinationURLs() throws GridServiceException,
                                                 RemoteException {

        ExtensibilityType queryResult
            = this.findServiceData(
                QueryHelper.getNameQuery(DEST_URLS_SDE_NAME));

        ServiceDataType serviceDataTypes
            = (ServiceDataType)AnyHelper.getAny(queryResult);

        Object[] destURLObjects = AnyHelper.getAny(serviceDataTypes);
        String[] destURLs = new String[destURLObjects.length];
        for (int i = 0; i < destURLObjects.length; i++) {
           destURLs[i] = (String) destURLObjects[i];
        }

        return destURLs;
    }

    private void updateDestinationURLs(String[] destURLs)
            throws GridServiceException {

        DestinationURLElement[] destURLElements
            = new DestinationURLElement[destURLs.length];
        for (int index=0; index<destURLs.length; index++) {
            destURLElements[index].setDestinationURL(destURLs[index]);
        }

        ServiceData destinationURLsServiceData =
            this.serviceData.create(DEST_URLS_SDE_NAME);
        destinationURLsServiceData.setValue(destURLElements);
        this.serviceData.add(destinationURLsServiceData);
    }

    public ServiceTerminationReferenceType createService(CreationType creation)
            throws RemoteException, ServiceAlreadyExistsFault,
            GridServiceFault {
        ServiceTerminationReferenceType retval = super.createService(creation);

        fileStreamingHandles.notifyChange();

        return retval;
    }


    public Object createServiceObject(CreationType creation)
            throws GridServiceException {
        extension = creation.getServiceParameters();
        Object obj = AnyHelper.getAny(extension);
        if(!(obj instanceof FileStreamingOptionsType)) {
            throw new GridServiceException(
                    "Invalid type for ServiceParameters");
        }
        FileStreamingOptionsType options = (FileStreamingOptionsType) obj;
        FileStreamingPortType serviceInstance
            = new FileStreamingImpl(fileStreamingAttributes, options);

        /*
        String destinationURL = options.getDestinationURL();

        //Get current destination URLs service data
        String[] currentDestURLs = null;
        try {
            currentDestURLs = getDestinationURLs();
        } catch (RemoteException re) {
            logger.error("problem obtaining service data", re);
        }
        
        //Append new instance's destination URL to local copy of service data
        String[] destURLs = new String[currentDestURLs.length+1];
        for (int index=0; index<currentDestURLs.length; index++) {
            destURLs[index] = currentDestURLs[index];
        }
        destURLs[destURLs.length-1] = destinationURL;

        //Update destination URLs service data
        updateDestinationURLs(destURLs);
        */

        return serviceInstance;
    }

    public void notifyDestroy(String path) {
        super.notifyDestroy(path);
        fileStreamingHandles.notifyChange();

        /*
        //Obtain the index into the list of instances of the dying instance
        String servicePath
            = (String) getProperty(ServiceProperties.SERVICE_PATH);
        ServiceNode serviceNode
            = ServiceNode.getRootNode().getNode(servicePath);
        Vector serviceInstances = serviceNode.getAllServices();
        int serviceInstanceCount = serviceInstances.size();
        int targetIndex = -1;
        for (int index=0; index<serviceInstanceCount; index++) {
            ServiceSkeleton service
                = (ServiceSkeleton) serviceInstances.elementAt(index);
            String instanceServicePath
                = (String) service.getProperty(ServiceProperties.SERVICE_PATH);
            if (path.equals(instanceServicePath)) {
                targetIndex = index;
                break;
            }
        }

        //Get current destination URLs service data
        String[] currentDestURLs = null;
        try {
            currentDestURLs = getDestinationURLs();
        } catch (RemoteException re) {
            logger.error("problem obtaining service data", re);
        }

        //Remove dying instance's destination URL from service data
        String[] destURLs = new String[currentDestURLs.length-1];
        for (int index=0; index<destURLs.length; index++) {
            if (index >= targetIndex) {
                //adjust for skipped/deleted element
                destURLs[index] = currentDestURLs[index+1];
            } else {
                destURLs[index] = currentDestURLs[index];
            }
        }

        //Update destination URLs service data
        /*
        try {
            updateDestinationURLs(destURLs);
        } catch (GridServiceException gse) {
            logger.error("problem updating service data", gse);
        }*/
    }

    public Object [] generateServiceDataValues(QName qname) {
        logger.debug("generating service data for " + qname.toString());

        if (qname.equals(FILE_STREAMING_HANDLES_SDE_QNAME)) {
            return getFileStreamingHandlesDataValues();
        } else {
            return null;
        }

    }

    protected Object [] getFileStreamingHandlesDataValues() {
        Object [] handles;
        String myHandle = (String) getProperty(ServiceProperties.HANDLE);

        String servicePath = (String) getProperty(
                ServiceProperties.SERVICE_PATH);
        logger.debug("First locating my ServiceNode at " + servicePath);
        ServiceNode node = ServiceNode.getRootNode().getNode(servicePath);
        Vector instances = node.getAllServices();
        int instanceCount = instances.size();
        logger.debug("Got " + String.valueOf(instanceCount-1)
                + " instance" + ((instanceCount-1>1) ? "s" : "")
                + " to deal with");

        handles = new Object[instanceCount-1];

        for (int i = 0, j = 0; i < instanceCount; i++) {
            ServiceSkeleton service = (ServiceSkeleton) instances.get(i);
            String handleString =
                    (String) service.getProperty(ServiceProperties.HANDLE);

            if (handleString.equals(myHandle)) {
                // Skip the factory---only list instances
                continue;
            }

            logger.debug("Adding instance #" + String.valueOf(i)
                    + ": " + handleString);

            HandleType handle = new HandleType(handleString);
            ServiceHandleElementType element = new ServiceHandleElementType();

            element.setServiceHandle(handle);

            handles[j++] = element;
        }
        return handles;
    }

}
