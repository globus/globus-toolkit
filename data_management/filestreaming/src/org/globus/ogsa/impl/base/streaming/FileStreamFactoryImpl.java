/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
package org.globus.ogsa.impl.base.streaming;

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Vector;

import javax.xml.namespace.QName;

import org.globus.gsi.proxy.IgnoreProxyPolicyHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.ogsa.GridContext;
import org.globus.ogsa.GridServiceException;
import org.globus.ogsa.base.streaming.FileStreamOptionsType;
import org.globus.ogsa.base.streaming.FileStreamOptionsWrapperType;
import org.globus.ogsa.base.streaming.FileStreamFactoryOptionsType;
import org.globus.ogsa.base.streaming.FileStreamFactoryOptionsWrapperType;
import org.globus.ogsa.base.streaming.FileStreamPortType;
import org.globus.ogsa.impl.ogsi.PersistentGridServiceImpl;
import org.globus.ogsa.impl.ogsi.GridServiceImpl;
import org.globus.ogsa.ServiceData;
import org.globus.ogsa.ServiceDataValueCallback;
import org.globus.ogsa.ServiceProperties;
import org.globus.ogsa.ServicePropertiesException;
import org.globus.ogsa.utils.AnyHelper;

import org.gridforum.ogsi.ExtensibilityType;

public class FileStreamFactoryImpl extends GridServiceImpl
                                   implements ServiceDataValueCallback {
    private static Log logger
        = LogFactory.getLog(FileStreamFactoryImpl.class);

    public static String SOURCE_PATH_SD_NAME = "sourcePath";

    public FileStreamFactoryImpl() {
        super ("File Stream Factory Service");
    }

    public void postCreate(GridContext context) throws GridServiceException {
        super.postCreate(context);

        ExtensibilityType creationExtensibility
            = (ExtensibilityType) getProperty(
                    ServiceProperties.CREATION_EXTENSIBILITY);

        FileStreamFactoryOptionsWrapperType factoryOptionsWrapper = null;
        try {
            factoryOptionsWrapper = (FileStreamFactoryOptionsWrapperType)
                    AnyHelper.getAsSingleObject(
                        creationExtensibility,
                        FileStreamFactoryOptionsWrapperType.class);
        } catch (ClassCastException cce) {
            throw new GridServiceException(
                "invalid service creation parameters type", cce);
        }
        FileStreamFactoryOptionsType factoryOptions
            = factoryOptionsWrapper.getFileStreamFactoryOptions();

        String sourcePath = factoryOptions.getSourcePath();
        if (logger.isDebugEnabled()) {
            logger.debug("saving source path as service data: " + sourcePath);
        }

        try {
            ServiceData sourcePathSd = this.serviceData.create("sourcePath");
            sourcePathSd.setValue(sourcePath);
            this.serviceData.add(sourcePathSd);
        } catch (GridServiceException gse) {
            logger.error("problem creating source path service data", gse);
        }
    }

    //*** ServiceDataValueCallback method ***//
    public Collection getServiceDataValues(QName qname) {
        if (qname.getLocalPart().equals(SOURCE_PATH_SD_NAME)) {
            ArrayList sdList = new ArrayList();
            Iterator sdIter = this.serviceData.iterator();
            while (sdIter.hasNext()) {
                ServiceData serviceData = (ServiceData) sdIter.next();
                sdList.add(serviceData.getName());
            }

            return sdList;
        }

        return new ArrayList();
    }
}
