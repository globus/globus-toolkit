package org.globus.gridftp;

import java.awt.*; 
import java.lang.*; 
import java.awt.event.*;
import java.io.*; 
import java.util.*; 

public class LineChart extends Axis 
{
  protected Vector  lines;
  protected Vector  colors;
  protected int     pointRadius = 3;
  protected boolean drawPointsOn = true;

  public LineChart(double minX, double maxX, double minY, double maxY)
   {
     super(minX, maxX, minY, maxY);

     lines = new Vector(5, 5);
     colors = new Vector(5, 5);
   }

  public LineChart(double minX, double maxX, double minY, double maxY, String title)
   {
     super(minX, maxX, minY, maxY, title);

     lines = new Vector(5, 5);
     colors = new Vector(5, 5);
   }

  public void addLine(Vector points, Color c)
   {
     lines.addElement(points);
     colors.addElement(c);
   }

  public void enableDrawPoints(boolean on)
   {
     drawPointsOn = on;
   }

  public void setPointRadius(int rad)
   {
     pointRadius = rad;
   }

  ////////////////////////////////////////////////////////////////
  //
  ////////////////////////////////////////////////////////////////
  private void drawLines(Graphics g)
   {
     int lineCount;
     int pointCount;
     int ctr;
     int ctr2;
     Point pt1;
     Point pt2;
     ColorPoint cPt1;
     ColorPoint cPt2;
     Vector currentLine;
     
     lineCount = lines.size();
     for(ctr = 0; ctr < lineCount; ctr++)
      {
        currentLine = (Vector)lines.elementAt(ctr);
        g.setColor((Color)colors.elementAt(ctr));
        pointCount = currentLine.size();
        for(ctr2 = 0; ctr2 < pointCount - 1; ctr2++)
         {
           cPt1 = (ColorPoint)currentLine.elementAt(ctr2);
           cPt2 = (ColorPoint)currentLine.elementAt(ctr2+1);

           pt1 = graphToScreen(cPt1.x, cPt1.y);
           pt2 = graphToScreen(cPt2.x, cPt2.y);

           g.drawLine(pt1.x, pt1.y, pt2.x, pt2.y);
           if(drawPointsOn)
            {
              g.fillOval(pt1.x-pointRadius, pt1.y-pointRadius,
                         pointRadius*2, pointRadius*2);
              if(ctr2 == pointCount - 2)
               {
                 g.fillOval(pt2.x-pointRadius, pt2.y-pointRadius,
                            pointRadius*2, pointRadius*2);
               }
            }
         }
      }
   }

  public void paint(Graphics g)
   {
     if(useDoubleBuffer)
      {
        draw(dbG);
        drawLines(dbG);
        g.drawImage(dbIma, 0, 0, this);
      }
     else
      {
        draw(g);
        drawLines(g);
      }
   }

}

