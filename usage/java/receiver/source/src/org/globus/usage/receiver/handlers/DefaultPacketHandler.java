package org.globus.usage.receiver.handlers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.PreparedStatement;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.usage.packets.CustomByteBuffer;
import org.globus.usage.packets.UsageMonitorPacket;
import org.globus.usage.receiver.HandlerThread;

public class DefaultPacketHandler implements PacketHandler {
    /*The handler that will be called when receiver gets an unknown code...
      because doCodesMatch always returns true, it handles anything. It
      will just write the packet to a database as a BLOB.*/

    private static Log log = LogFactory.getLog(DefaultPacketHandler.class);

    protected String dburl;
    protected String table;
    protected Connection con;

    /*Gets a database connection from the pool created by the HandlerThread.
     table is the name of the table in that database to write packets to.*/
    public DefaultPacketHandler(String dburl, String table) throws SQLException {
	//        this.dburl = dburl;
        this.table = table;

	con = DriverManager.getConnection(HandlerThread.dbPoolName);
    }

    public void finalize() {

	if( con != null ) {
	    try { con.close(  ); }                
	    catch( Exception e ) { }
	}
    }

    public boolean doCodesMatch(short componentCode, short versionCode) {
        return true;
    }

    public UsageMonitorPacket instantiatePacket(CustomByteBuffer rawBytes) {
        return new UsageMonitorPacket();
    }
   
    public void handlePacket(UsageMonitorPacket pack) {
        Connection con = null;
        PreparedStatement stmt;

        try {
            
            log.debug("Will write this packet to database table"
                + table + ": ");

            log.info(pack.toString());

            stmt = makeSQLInsert(pack);
            stmt.executeUpdate();
            stmt.close();
        }
        
        catch( SQLException e ) {
            log.error(e.getMessage());
	    log.error("Packet contents:"+ new String(pack.getBinaryContents()));
        }

    }

    /*If you want to write a handler that writes packets into a database,
      subclass DefaultPacketHandler and just override makeSQLInsert to
      return the right SQL statement..*/
    protected PreparedStatement makeSQLInsert(UsageMonitorPacket pack) throws SQLException{
	/*For better performance, save this statement and reuse it.*/
	PreparedStatement ps = con.prepareStatement("INSERT INTO "+ table +  " (componentcode, versioncode, contents) VALUES(?, ?, ?);");
           
	ps.setShort(1, pack.getComponentCode());
	ps.setShort(2, pack.getPacketVersion());
	ps.setBytes(3, pack.getBinaryContents());

	return ps;
    }
}
