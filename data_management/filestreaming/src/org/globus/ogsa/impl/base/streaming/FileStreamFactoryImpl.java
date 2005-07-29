/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
package org.globus.ogsa.impl.base.streaming;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;

import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.ogsa.GridContext;
import org.globus.ogsa.GridServiceException;
import org.globus.ogsa.base.streaming.FileStreamFactoryOptionsType;
import org.globus.ogsa.base.streaming.FileStreamFactoryOptionsWrapperType;
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

    public static String FSF_NAMESPACE
        = "http://www.globus.org/namespaces/2003/04/base/streaming";
    public static QName SOURCE_PATH_SD_QNAME =
        new QName(FSF_NAMESPACE, "sourcePath");
    public static QName FILE_SIZE_SD_QNAME =
        new QName(FSF_NAMESPACE, "fileSize");
    private File path;

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

        this.path = new File(sourcePath);

        try {
            ServiceData sourcePathSd = this.serviceData.create(
                    SOURCE_PATH_SD_QNAME);
            sourcePathSd.setValue(sourcePath);
            this.serviceData.add(sourcePathSd);

            ServiceData fileSizeSd = this.serviceData.create(
                    FILE_SIZE_SD_QNAME);
            fileSizeSd.setCallback(this);
            this.serviceData.add(fileSizeSd);
        } catch (GridServiceException gse) {
            logger.error("problem creating source path service data", gse);
        }
    }

    public Collection getServiceDataValues(QName qname) {
        if (qname.equals(FILE_SIZE_SD_QNAME)) {
            Integer l = new Integer((int) path.length());
            logger.debug("query of file size will return " + l.toString());

            ArrayList al = new ArrayList(1);
            al.add(l);

            return al;
        } else {
            return super.getServiceDataValues(qname);
        }
    }
}
