package org.globus.usage.receiver.handlers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;

public class DefaultPacketHandler implements PacketHandler {
    /*The handler that will be called when receiver gets an unknown code...
      because doCodesMatch always returns true, it handles anything. It
      will just write the packet to a database as a BLOB.*/

    private static Log log = LogFactory.getLog(DefaultPacketHandler.class);

    String dburl;
    String table;
    String driverClass;

    /*Pass in for example ("org.gjt.mm.mysql.Driver", "jdbc:mysql://localhost/menagerie?user=javaprog&password=letmein")*/

    public DefaultPacketHandler(String driverClass, String dburl, String table) {
        //this should be full JDBC URL for the database.
        this.dburl = dburl;
        this.table = table;
        this.driverClass = driverClass;
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return true;
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new UsageMonitorPacket();
    }
   
    public void handlePacket(UsageMonitorPacket pack) {
        Connection con = null;
        Statement stmt;

        try {
            
            log.debug("Will write this packet to database table"
                + table + ": ");

            log.info(pack.toString());


            Class.forName(driverClass);
            con = DriverManager.getConnection(dburl);

            stmt = con.createStatement();
            stmt.executeUpdate("INSERT INTO "+ table +
                               makeSQLInsert(pack) +";");

            stmt.close();
        }
        
        catch( SQLException e ) {
            e.printStackTrace(  );
        }
        catch(ClassNotFoundException e) {
            log.error("Can't find driver class " + driverClass);
        }

        finally {
            if( con != null ) {
                try { con.close(  ); }                
                catch( Exception e ) { }
            }
        }
    }

    /*If you want to write a handler that writes packets into a database,
      subclass DefaultPacketHandler and just override makeSQLInsert to
      return the right SQL string.*/
    protected String makeSQLInsert(UsageMonitorPacket pack) {
        return new String(
            " (componentcode, versioncode, contents) VALUES('" +
            pack.getComponentCode() + "','" +
            pack.getPacketVersion() + "','" +
            pack.getBinaryContents() + "')");
    }
}
