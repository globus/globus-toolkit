package org.globus.ogsa.impl.base.streaming;

import java.rmi.RemoteException;

import org.globus.ogsa.base.streaming.FileStreamFactoryAttributes;
import org.globus.ogsa.GridContext;
import org.globus.ogsa.GridServiceException;
import org.globus.ogsa.ServiceProperties;
import org.globus.ogsa.impl.ogsi.PersistentGridServiceImpl;
import org.globus.ogsa.utils.AnyHelper;

import org.gridforum.ogsi.ExtensibilityType;

public class FileStreamFactoryFactoryImpl extends PersistentGridServiceImpl {

    public FileStreamFactoryFactoryImpl() {
        super ("File Stream Factory Factory");
    }
    
    public Object createServiceObject(ExtensibilityType creationParameters)
            throws GridServiceException {
        FileStreamFactoryImpl factoryInstance = null;

        try {
            if (creationParameters != null) {
                Object obj = AnyHelper.getAsSingleObject(creationParameters);
                if (!(obj instanceof FileStreamFactoryAttributes)) {
                    throw new GridServiceException(
                            "Invalid ServiceParameter type: "
                            + obj.getClass()
                            + "--expected "
                            + FileStreamFactoryAttributes.class.getName());
                }
                FileStreamFactoryAttributes factoryAttributes =
                    (FileStreamFactoryAttributes) obj;
                String localPath = factoryAttributes.getSourcePath();

                factoryInstance = new FileStreamFactoryImpl(factoryAttributes);
            } else {
                factoryInstance = new FileStreamFactoryImpl();
            }
            factoryInstance.setProperty(
                "name",
                "File Stream Factory");
            factoryInstance.setProperty(
                "schemaPath",
                "schema/base/streaming/file_stream_factory_service.wsdl");
            factoryInstance.setProperty(
                "baseClassName",
                "org.globus.ogsa.impl.base.streaming.FileStreamFactoryImpl");
            factoryInstance.setProperty(
                "className",
                "org.globus.ogsa.base.streaming.FileStreamFactoryPortType");
            factoryInstance.setProperty(
                "operationProviders",
                "org.globus.ogsa.impl.ogsi.FactoryProvider");
            factoryInstance.setProperty(
                "persistent",
                "true");
            factoryInstance.setProperty(
                "factoryCallback",
                "org.globus.ogsa.impl.ogsi.DynamicFactoryCallbackImpl");
            factoryInstance.setProperty(
                "handlerClass",
                "org.globus.ogsa.handlers.RPCURIProvider");
            factoryInstance.setProperty(
                "allowedMethods",
                "*");
            factoryInstance.setProperty(
                "instance-name",
                "File Stream");
            factoryInstance.setProperty(
                "instance-schemaPath",
                "schema/base/streaming/file_stream_service.wsdl");
            factoryInstance.setProperty(
                "instance-baseClassName",
                "org.globus.ogsa.impl.base.streaming.FileStreamImpl");
            factoryInstance.setProperty(
                "instance-className",
                "org.globus.ogsa.base.streaming.FileStreamPortType");
            factoryInstance.setProperty(
                "instance-operationProviders",
                "org.globus.ogsa.impl.ogsi.FactoryProvider");
                /*
                org.globus.ogsa.impl.security.authentication.SecureConversationProvider");
                */
        } catch (RemoteException re) {
            throw new GridServiceException("Error creating FactoryImpl",
                                           re);
        }

        return factoryInstance;
    }
}
