package org.globus.usage.receiver.samples;

import java.io.InputStream;
import java.io.IOException;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.receiver.Receiver;
import org.globus.usage.receiver.handlers.GridFTPPacketHandler;

/*An example of how the Receiver class can be used in a program:*/
public class ExampleReceiver {

    static Log log = LogFactory.getLog(ExampleReceiver.class);

    public static void main(String[] args) {
        int port = 0;
        String databaseDriverClass, databaseURL, defaultTable, gftpTable;
        Properties props;
        InputStream propsIn;
        Receiver receiver;
        GridFTPPacketHandler gftpHandler;


        /*Open properties file (which gets compiled into jar) to read
          default port and database connection information:*/
        try {
            props = new Properties();
            propsIn = Receiver.class.getResourceAsStream("/receiver.properties");
            if (propsIn != null) {
                props.load(propsIn);
            }
	    else {
		log.error("Can't open properties file receiver.properties.");
	    }

            databaseDriverClass = props.getProperty("database-driver");
            databaseURL = props.getProperty("database-url");
            defaultTable = props.getProperty("default-table");
            gftpTable = props.getProperty("gftp-table");
            

            if (args.length == 1)
                /*Get listening port number from command line*/
                port = Integer.parseInt(args[0]);
            else {
                /*or else, read port from properties file:*/
                port = Integer.parseInt(props.getProperty("listening-port"));
            }
            
            if (port == 0) {
                throw new Exception("You must specify listening port either on the command line or in the properties file.");
            }
            
            /*When creating the receiver, pass it the port to listen on,
              the database connection class to use, the url to connect to your
              database, and the database table where default packets will be
	      written if no other handler takes them:*/
	    log.info("Starting receiver on port "+port+"; will write to database at "+databaseURL+".");
            receiver = new Receiver(port, 
                                    databaseDriverClass, 
                                    databaseURL,
                                    defaultTable);
            
            /*gftpHandler is an example of a PacketHandler subclass.  I create
              one here, giving it the neccessary database infomration, and then
              register it to the receiver; it knows what to do with all incoming
              GFTP usage packets.*/
            gftpHandler = new GridFTPPacketHandler(databaseDriverClass,
                                                   databaseURL,
                                                   gftpTable);
            receiver.registerHandler(gftpHandler);

            
        }
        catch (IOException e) {
            log.fatal("An IOException occurred when trying to create Receiver:" +e.getMessage());
        }
        catch (Exception e) {
            log.fatal("An exception occurred: " + e.getMessage(), e);
        }

        /*That's all... this thread ends, but the receiver has started listener
          and handler threads which will write incoming packets to the database.*/
    }
}
