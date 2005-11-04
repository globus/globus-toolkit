package org.globus.gridftp;

import java.util.*;
import java.awt.event.*;
import java.awt.*;
import javax.swing.*;
import java.net.*;
import java.lang.*;
import java.io.*;
import javax.swing.border.*;

public
class
GridFTPUsageViewer
    implements Runnable,
        WindowListener
{
    private double                      maxY;
    private int                         intervalBytes = 0;

    private Vector                      linePts;
    private LineChart                   lineChart;
    private long                        totalBytes = 0;
    private int                         transferCount = -1;
    protected JFrame                    mainFrame;
    private Thread                      netThread;
    private Thread                      graphThread;
    private boolean                     done = false;
    protected DatagramSocket            socket;
    protected JLabel                    countLabel;
    protected JLabel                    timeLabel;
    protected JLabel                    bytesLabel;
    protected JLabel                    imageLabel;
    protected JLabel                    bottomL;
    private Hashtable                   imageTable = null;

    public
    static void main(
        String                          argv[])
    {
        String                          imageFile = null;
        int                             port = 0;
        GridFTPUsageViewer              viewer;

        try
        {
            try
            {
                port = new Integer(argv[0]).intValue();
                if(argv.length > 1)
                {
                    imageFile = argv[1];
                }
            }
            catch(Exception e)
            {
                port = 0;
            }
            viewer = new GridFTPUsageViewer(port, imageFile);
        }
        catch(Exception e)
        {
            e.printStackTrace();
            System.err.println(e);
        }
    }

    public
    GridFTPUsageViewer(
        int                             port,
        String                          imageMapFile)
            throws Exception
    {
        InetAddress                     addr;
        JPanel                          mainP;
        JPanel                          tmpP;
        JLabel                          tmpL;
        JPanel                          imageP;

        linePts = new Vector();
        socket = new DatagramSocket(port);
        addr = socket.getLocalAddress();

        /* arrange the GUI */
        mainFrame = new JFrame("GridFTP Usage");
        mainP = new JPanel();
        mainFrame.getContentPane().add(mainP);
        mainP.setLayout(new BorderLayout(10, 10));
        countLabel = new JLabel("Total Files Transfer: 0");
        tmpP = new JPanel();
        tmpP.setLayout(new GridLayout(6, 1));
        tmpP.setBorder(
            new CompoundBorder(
                new EtchedBorder(EtchedBorder.RAISED),
                new EmptyBorder(1, 5, 1, 5)));
        mainP.add("West", tmpP);
        tmpP.add(countLabel);
        bytesLabel = new JLabel();
        bytesLabel.setText("Total Bytes Transfer: " +
             new Long(totalBytes).toString());
        tmpP.add(bytesLabel);
        timeLabel = new JLabel("Last Time: 0");
        tmpP.add(timeLabel);

/*
        imageP = new JPanel();
        imageP.setBorder(
            new CompoundBorder(
                new EtchedBorder(EtchedBorder.RAISED),
                new EmptyBorder(1, 5, 1, 5)));
        this.imageLabel = new JLabel();

        imageP.add(this.imageLabel);
        mainP.add("Center", imageP);
*/
        this.maxY = 1.0; // staret wiuth 1Mb/s
        lineChart = new LineChart(0.0, 10.0, 0.0, this.maxY);
        lineChart.setAxisColor(Color.green);
        lineChart.setTicColor(Color.green);
        lineChart.setBackground(Color.black);
        lineChart.autoRepaintEnable(true);
        lineChart.enableGridLines(false, true);
        lineChart.setTicIncrement(1.0, this.maxY/10.0);
        lineChart.enableDrawPoints(false);
        lineChart.addLine(linePts, Color.green);
        lineChart.enableTicLabels(false);
        lineChart.setTitle(new Double(this.maxY).toString());
        mainP.add("Center", this.lineChart);

        String listenStr = new String("listening on UDP port: " +
            new Integer(socket.getLocalPort()).toString());
        System.err.println(listenStr);

        tmpP = new JPanel();
        bottomL = new JLabel(listenStr);
        tmpP.setBorder(
            new CompoundBorder(
                new EtchedBorder(EtchedBorder.RAISED),
                new EmptyBorder(1, 1, 1, 1)));
        tmpP.add(bottomL);
        mainP.add("South", tmpP);

        this.updateValues("00:00:00", 0);

        netThread = new Thread(this);
        netThread.start();
        graphThread = new Thread(this);
        graphThread.start();
        mainFrame.setSize(470, 295);
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

        return out;
    }

    public void
    run()
    {
        boolean                         done;
        int                             start_ndx;
        int                             ndx;
        int                             i;
        long                            time;
        byte                            recv_buf[];
        byte                            end_del;
        int                             recv_len;
        byte                            buf[] = new byte[1500];
        DatagramPacket                  packet;
        String                          key;
        String                          val;
        String                          timeS = "";
        long                            nbytes = 0;
        int                             hourBump;

        if(Thread.currentThread() == netThread)
        {
            TimeZone tz = TimeZone.getDefault();
            hourBump = tz.getRawOffset() / 1000 / 60 / 60;

            packet = new DatagramPacket(buf, buf.length);
            while(!this.done)
            {
                try
                {
                    socket.receive(packet);
                    recv_buf = packet.getData();
                    recv_len = packet.getLength();

                    String logMsg = new String(
                        recv_buf, 20, recv_len-20, "US-ASCII");
                    System.out.println(logMsg);

                    time = (long)this.convertInt(recv_buf, 19);
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
                        if(key.equals("END"))
                        {
                            int     hourI;
                            hourI = 
                                new Integer(val.substring(8, 10)).intValue();

                            hourI += hourBump;
                            if(hourI >= 24) hourI -= 24;
                            else if(hourI < 0) hourI += 24;

                            String minS = val.substring(10, 12);
                            String secS = val.substring(12, 14);
                            timeS = new String(hourI +":"+minS+":"+secS);
                        }
                        if(key.equals("NBYTES"))
                        {
                            synchronized(this)
                            {
                                intervalBytes += nbytes;
                            }
                            nbytes = new Long(val).longValue();
                            done = true;
                        }
                    }
                    this.updateValues(timeS, nbytes);
                }
                catch(Exception e)
                {
                    e.printStackTrace();
                    System.err.println(e);
                }
            }
        }
        else
        {
            String                      suffS;
            String                      maxYStr;
            ColorPoint                  cp;
            double                      bps;
            while(!this.done)
            {
                synchronized(this)
                {
                    try
                    {
                        this.wait(5000);
                    }
                    catch (Exception w)
                    {
                    }

                    bps = (double)intervalBytes / 1024.0;
                    if(bps > this.maxY)
                    {
                        this.maxY = bps + (bps * .1);
                        lineChart.setTicIncrement(1.0, this.maxY/10.0);
                        lineChart.rescale(0.0, 10.0, 0.0, this.maxY);
                    }
                    intervalBytes = 0;
                }
                /* update graph */
                if(linePts.size() > 10)
                {
                    linePts.removeElementAt(0);
                }
                linePts.addElement(new ColorPoint(9.0, bps, Color.green));

                double ym = 0.0;
                for(i = 0; i < linePts.size(); i++)
                {
                    cp = (ColorPoint)linePts.elementAt(i);
                    cp.x = i;
                    if(cp.y > ym) ym = cp.y;
                }

                if(ym < this.maxY*0.02)
                {
                    this.maxY = ym + (ym *.1);
                    lineChart.setTicIncrement(1.0, this.maxY/10.0);
                    lineChart.rescale(0.0, 10.0, 0.0, this.maxY);
                }

                if(this.maxY > 1024.0*1024.0)
                {
                    maxYStr = new Double(this.maxY/1024.0/1024.0).toString();
                    suffS = " GB per Interval";
                }
                else if(this.maxY > 1024.0)
                {
                    maxYStr = new Double(this.maxY/1024.0).toString();
                    suffS = " MB per Interval";
                }
                else
                {
                    maxYStr = new Double(this.maxY).toString();
                    suffS = " KB per Interval";
                }
                ndx = maxYStr.indexOf('.');
                if(ndx > 0)
                {
                    maxYStr = maxYStr.substring(0, ndx);
                }
                bottomL.setText("Graph range 0 - " + maxYStr + suffS);
                lineChart.repaint();
            }
        }
    }

    protected
    void
    loadImageArray(
        String                          mapfile)
    {
        int                             ndx;
        Hashtable                       table = null;
        String                          line;
        ImageIcon                       imageI;
        String                          key;
        String                          filename;

        if(mapfile == null)
        {
            return;
        }
        try
        {
            BufferedReader br = new BufferedReader(new FileReader(mapfile));
            table = new Hashtable();
            line = br.readLine();
            while(line != null)
            {
                ndx = line.indexOf(':');
                key = line.substring(0, ndx);
                filename = line.substring(ndx + 1);
                System.out.println("loading " + filename + " for " + key);
                imageI = new ImageIcon(filename);
                if(imageI == null)
                {
                    return;
                }
                table.put(new Integer(key), imageI);
                line = br.readLine();
            }
            this.imageTable = table;
        }
        catch(Exception e)
        {
            this.imageTable = null;
            System.err.println(e);
        }
    }

    protected 
    void
    updateValues(
        String                          timeS,
        long                            nbytes)
    {
        int                             ndx;
        String                          suf;
        String                          bS;
        double                          tb;
        ImageIcon                       imageI;

        totalBytes += nbytes;
        timeLabel.setText("Last Transfer Time: "+ timeS);

        if(totalBytes > 1024.0*1024.0*1204.0)
        {
            tb = totalBytes /1024.0/1024.0/1024.0;
            suf = "GB";
        }
        else if(totalBytes > 1024.0*1024.0)
        {
            tb = totalBytes /1024.0/1024.0;
            suf = "MB";
        }
        else if(totalBytes > 1024.0)
        {
            tb = totalBytes / 1024.0;
            suf = "KB";
        }
        else
        {
            tb = totalBytes;
            suf = "B";
        }

        bS = new Double(tb).toString();
        ndx = bS.indexOf('.');
        if(ndx > 0 && bS.length() > ndx+3)
        {
            bS = bS.substring(0, ndx+3);
        }

        bytesLabel.setText("Total Bytes Transfer: " + bS + suf);
        transferCount++;
        countLabel.setText("Total Files Transfer: " + new Integer(
            transferCount).toString());

        if(this.imageTable == null)
        {
            return;
        }
        imageI = (ImageIcon) this.imageTable.get(new Integer(transferCount));
        if(imageI != null)
        {
            this.imageLabel.setIcon(imageI);
        }
    }

    public
    void
    windowActivated(WindowEvent e)
    {
        mainFrame.repaint();
        lineChart.repaint();
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
        mainFrame.repaint();
        lineChart.repaint();
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
