package org.globus.ogsa.impl.base.gram.filestreaming;

import java.rmi.RemoteException;

import org.globus.ogsa.base.gram.filestreaming.FileStreamingType;
import org.globus.ogsa.impl.core.factory.SecureFactoryServiceSkeleton;
import org.globus.ogsa.GridServiceException;
import org.globus.ogsa.utils.AnyHelper;

import org.gridforum.ogsa.CreationType;
import org.gridforum.ogsa.ExtensibilityType;

public class FileStreamingFactoryFactory 
    extends SecureFactoryServiceSkeleton {
    
    public FileStreamingFactoryFactory() {
        super ("File Streaming Factory Factory");
    }
    public Object createServiceObject(CreationType creation)
            throws GridServiceException {
        ExtensibilityType extension = creation.getServiceParameters();
        FileStreamingFactoryImpl factory;

        try {
            if (extension != null) {
                Object obj = AnyHelper.getAny(extension);
                if (!(obj instanceof FileStreamingType)) {
                    throw new GridServiceException(
                            "Invalid ServiceParameter type: "
                            + obj.getClass()
                            + " expected FileStreamingLocalPathType");
                }
                FileStreamingType path =
                        (FileStreamingType) obj;
                String localPath = path.getPath();

                factory = new FileStreamingFactoryImpl(path);
            } else {
                factory = new FileStreamingFactoryImpl();
            }
            factory.setProperty("allowedMethods", "*");
            factory.setProperty("className", factory.getClass());
            factory.setProperty("schemaPath",
                    "schema/core/factory/secure_factory_service.wsdl");
            factory.setProperty("instanceSchemaPath",
                    "schema/base/gram/file_streaming_service.wsdl");
            factory.setProperty("handlerClass",
                    "org.globus.ogsa.handlers.RPCURIProvider");
        } catch (RemoteException re) {
            throw new GridServiceException("Error creating FactoryImpl",
                    re);
        }

        return factory;
    }
}
