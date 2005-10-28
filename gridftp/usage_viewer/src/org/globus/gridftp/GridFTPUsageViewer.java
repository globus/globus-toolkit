package org.globus.gridftp;

import java.util.*;
import java.awt.event.*;
import java.awt.*;
import javax.swing.*;
import java.net.*;
import java.lang.*;
import javax.swing.border.*;

public
class
GridFTPUsageViewer
    implements Runnable,
        WindowListener
{
    private long                        totalBytes = 0;
    private int                         transferCount = 0;
    protected JFrame                    mainFrame;
    private Thread                      netThread;
    private boolean                     done = false;
    protected DatagramSocket            socket;
    protected JLabel                    countLabel;
    protected JLabel                    timeLabel;
    protected JLabel                    bytesLabel;

    public
    static void main(
        String                          argv[])
    {
        int                             port = 0;
        GridFTPUsageViewer              viewer;

        try
        {
            try
            {
                port = new Integer(argv[0]).intValue();
            }
            catch(Exception e)
            {
                port = 0;
            }
            viewer = new GridFTPUsageViewer(port);
        }
        catch(Exception e)
        {
            System.err.println(e);
        }

    }

    public
    GridFTPUsageViewer(
        int                             port)
            throws Exception
    {
        InetAddress                     addr;
        JPanel                          mainP;
        JPanel                          tmpP;
        JLabel                          tmpL;

        socket = new DatagramSocket(port);
        addr = socket.getLocalAddress();

        /* arrange the GUI */
        mainFrame = new JFrame("GridFTP Usage");
        mainP = new JPanel();
        mainFrame.getContentPane().add(mainP);
        mainP.setLayout(new BorderLayout(10, 10));
        countLabel = new JLabel("Total Files Transfer: 0");
        tmpP = new JPanel();
        tmpP.setLayout(new GridLayout(5, 1));
        tmpP.setBorder(new EtchedBorder(EtchedBorder.RAISED));
        mainP.add("Center", tmpP);
        tmpP.add(countLabel);
        timeLabel = new JLabel("Last Time: 0");
        tmpP.add(timeLabel);
        bytesLabel = new JLabel();
        bytesLabel.setText("Total Bytes Transfer: " +
             new Long(totalBytes).toString());
        tmpP.add(bytesLabel);

        String listenStr = new String("listening at: " + addr.toString() +
            ":"+ new Integer(socket.getLocalPort()).toString());
        System.err.println(listenStr);
        tmpP = new JPanel();
        tmpL = new JLabel(listenStr);
        tmpP.add(tmpL);
        mainP.add("South", tmpP);
        netThread = new Thread(this);
        netThread.start();
        mainFrame.setSize(400, 200);
        mainFrame.addWindowListener(this);
        mainFrame.setVisible(true);
    }

    private int
    convertInt(
        byte                            buf[],
        int                             offset)
    {
        int                             i;
        int                             out = 0;

        for(i = 0; i < 4; i++)
        {
            int tmpI = (int)buf[offset+i];
            out += tmpI;
            out = out << 8;
        }
/*
        for(i = 3; i >= 0; i--)
        {
            out = (out << 8);
            out |= (buf[offset+i] & 0xFF);
        }
*/

        return out;
    }

    private short
    convertShort(
        byte                            buf[],
        int                             offset)
    {
        int                             i;
        short                           out = 0;

        for(i = 1; i >= 0; i--)
        {
            out = (short)(out << 8);
            out |= (buf[offset+i] & 0xFF);
        }
        return out;
    }

    public void
    run()
    {
        boolean                         done;
        int                             start_ndx;
        int                             ndx;
        long                            time;
        byte                            recv_buf[];
        byte                            end_del;
        int                             recv_len;
        byte                            buf[] = new byte[1500];
        DatagramPacket                  packet;
        String                          key;
        String                          val;

        packet = new DatagramPacket(buf, buf.length);
        while(!this.done)
        {
            try
            {
                socket.receive(packet);
                recv_buf = packet.getData();
                recv_len = packet.getLength();

                time = (long)this.convertInt(recv_buf, 19);
System.out.println("time-> " + time);
                ndx = 24; // skip ip crap
                done = false;

                while(!done)
                {
                    end_del = (byte)' ';
                    for(start_ndx = ndx; recv_buf[ndx] != (byte)'='; ndx++)
                    {
                    }
                    key = new String(recv_buf, start_ndx, ndx-start_ndx);
                    ndx++; // move past the =
                    if(recv_buf[ndx] == (byte)'"')
                    {
                        end_del = (byte)'"';
                        ndx++; // move past the "
                    }
                    /* this will not work for \", but so what for a 
                        crappy lil demo */
                    for(start_ndx = ndx; recv_buf[ndx] != end_del; ndx++)
                    {
                    }
                    val = new String(recv_buf, start_ndx, ndx-start_ndx);
                    ndx++; // move past the ' ' or '"'
                    if(end_del == (byte)'"')
                    {
                        ndx++; // move past the next space
                    }
                    if(key.equals("NBYTES"))
                    {
                        totalBytes += new Long(val).intValue();
                        bytesLabel.setText("Total Bytes Transfer: " + 
                            new Long(totalBytes).toString());
                        done = true;
                    }
                }
                transferCount++;
                countLabel.setText("Total Files Transfer: " + new Integer(
                    transferCount).toString());
            }
            catch(Exception e)
            {
                System.err.println(e);
            }
        }
    }

    public
    void
    windowActivated(WindowEvent e)
    {
    }

    public
    void
    windowClosed(WindowEvent e)
    {
    }

    public
    void
    windowClosing(WindowEvent e)
    {
        System.exit(0);
    }

    public
    void
    windowDeactivated(WindowEvent e)
    {
    }

    public
    void
    windowDeiconified(WindowEvent e)
    {
    }

    public
    void
    windowIconified(WindowEvent e)
    {
    }

    public
    void
    windowOpened(WindowEvent e)
    {
    }

}
