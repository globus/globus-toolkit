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
package org.globus.ogsa.impl.base.filestreaming;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.rmi.RemoteException;

import javax.xml.namespace.QName;

import org.globus.ogsa.base.filestreaming.DestinationURLElement;
import org.globus.ogsa.base.filestreaming.FileStreamAttributes;
import org.globus.ogsa.base.filestreaming.FileStreamFactoryAttributes;
import org.globus.ogsa.base.filestreaming.FileStreamPortType;
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

public class FileStreamFactoryImpl extends SecureFactoryServiceSkeleton
                                   implements ServiceDataValueCallback {
    private static Log logger
        = LogFactory.getLog(FileStreamFactoryImpl.class);

    private FileStreamFactoryAttributes fileStreamFactoryAttributes;
    /*
    private static final String DEST_URLS_SDE_NAME = "destinationURLs";
    private ServiceData fileStreamHandles;
    */
    private static final String FILE_STREAM_HANDLES_SDE_NAME
            = "fileStreamHandles";

    public FileStreamFactoryImpl() {
        super ("File Stream Factory Service");

        this.secContextSkeleton.setGrimPolicyHandler(
                new IgnoreProxyPolicyHandler());
    }

    public FileStreamFactoryImpl(
            FileStreamFactoryAttributes fileStreamFactoryAttributes)
            throws RemoteException {
        super ("File Stream Factory Service");
        this.secContextSkeleton.setGrimPolicyHandler(
                new IgnoreProxyPolicyHandler());

        this.fileStreamFactoryAttributes = fileStreamFactoryAttributes;
        fileStreamHandles = this.serviceData.create(
                FILE_STREAM_HANDLES_SDE_NAME);
        fileStreamHandles.setCallback(this);
        this.serviceData.add(fileStreamHandles);

        try {
            String factoryAttributes
                = this.fileStreamFactoryAttributes.getPath();
            flush();
        } catch (ServicePropertiesException spe) {
            throw new RemoteException("problem storing persistent properties",
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

    /*
    private void updateDestinationURLs(String[] destURLs)
            throws GridServiceException {

        ServiceData destinationURLsServiceData =
            this.serviceData.create(DEST_URLS_SDE_NAME);
        for (int index=0; index<destURLs.length; index++) {
            destinationURLsServiceData.addValue(destURLs[index]);
        }
        this.serviceData.add(destinationURLsServiceData);
    }
    */

    public ServiceTerminationReferenceType createService(CreationType creation)
            throws RemoteException, ServiceAlreadyExistsFault,
            GridServiceFault {
        ServiceTerminationReferenceType retval = super.createService(creation);

        fileStreamHandles.notifyChange();

        return retval;
    }

    public Object createServiceObject(CreationType creation)
            throws GridServiceException {
        ExtensibilityType extension = creation.getServiceParameters();
        Object obj = AnyHelper.getAny(extension);
        if(!(obj instanceof FileStreamAttributes)) {
            throw new GridServiceException(
                    "Invalid type for ServiceParameters");
        }
        FileStreamAttributes options = (FileStreamAttributes) obj;
        FileStreamPortType serviceInstance
            = new FileStreamImpl(this.fileStreamFactoryAttributes, options);

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
        fileStreamHandles.notifyChange();

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

        if (qname.localPart.equals(FILE_STREAM_HANDLES_QNAME)) {
            return getFileStreamHandlesDataValues();
        } else {
            return null;
        }

    }

    protected Object [] getFileStreamHandlesDataValues() {
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
