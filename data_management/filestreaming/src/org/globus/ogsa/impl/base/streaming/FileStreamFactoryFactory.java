package org.globus.ogsa.impl.base.streaming;

import java.rmi.RemoteException;

import org.globus.ogsa.base.streaming.FileStreamType;
import org.globus.ogsa.impl.core.factory.FactoryServiceSkeleton;
import org.globus.ogsa.impl.core.factory.FactoryDelegationSkeleton;
import org.globus.ogsa.GridContext;
import org.globus.ogsa.GridServiceException;
import org.globus.ogsa.ServiceProperties;
import org.globus.ogsa.utils.AnyHelper;

import org.gridforum.ogsa.CreationType;
import org.gridforum.ogsa.ExtensibilityType;

public class FileStreamFactoryFactory 
        extends FactoryServiceSkeleton {

    public FileStreamFactoryFactory() {
        super ("File Stream Factory Factory");
    }

    public void preCreate(ServiceProperties factory)
        throws GridServiceException {
    }

    public void postPersistentCreate(GridContext context)
            throws GridServiceException {
        setProperty(ServiceProperties.FACTORY, this);
        this.factorySkeleton = new FactoryDelegationSkeleton();
        this.factorySkeleton.setBase(this);
    }
    
    public Object createServiceObject(CreationType creation)
            throws GridServiceException {
        FileStreamFactoryImpl factory = null;

        try {
            ExtensibilityType extension = creation.getServiceParameters();
            if (extension != null) {
                Object obj = AnyHelper.getAny(extension);
                if (!(obj instanceof FileStreamType)) {
                    throw new GridServiceException(
                            "Invalid ServiceParameter type: "
                            + obj.getClass()
                            + " expected " + FileStreamType.class.getName());
                }
                FileStreamType path =
                        (FileStreamType) obj;
                String localPath = path.getPath();

                factory = new FileStreamFactoryImpl(path);
            } else {
                factory = new FileStreamFactoryImpl();
            }
            factory.setProperty("allowedMethods", "*");
            factory.setProperty("className", factory.getClass());
            factory.setProperty(
                    "schemaPath",
                    "schema/core/factory/secure_factory_service.wsdl");
            factory.setProperty(
                    "instanceSchemaPath",
                    "schema/base/streaming/file_stream_service.wsdl");
            factory.setProperty(
                    "handlerClass",
                    "org.globus.ogsa.handlers.RPCURIProvider");
        } catch (RemoteException re) {
            throw new GridServiceException("Error creating FactoryImpl",
                    re);
        }

        return factory;
    }
}
