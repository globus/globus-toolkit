/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.globus.gridftp;

import java.awt.*; 
import javax.swing.*; 
import java.lang.*; 
import java.awt.event.*;
import java.io.*; 
import java.util.*; 

public class Axis extends JPanel implements ComponentListener
{
  /** Leftmost value displayed on the x-axis. */
  protected double  minX = 0;
  /** Rightmost value displayed on the x-axis. */
  protected double  maxX = 10;
  /** Lowest value displayed on the y-axis. */
  protected double  minY = 0;
  /** Highest value displayed on the y-axis. */
  protected double  maxY = 10;

  private Color     titleColor=Color.black;
  private Color     axisColor = Color.black;
  private Color     ticColor = Color.black;

  private int       xAxisLength;
  private int       yAxisLength;

  private int       originX;
  private int       originY;

  private double    xAxisPosition = 0;
  private double    yAxisPosition = 0;

  /** Ratio of data x-coordinate to displayed x-coordinate. */
  protected double  scaleX;
  /** Ratio of data y-coordinate to displayed y-coordinate. */
  protected double  scaleY;

  private boolean   titleOn = true;
  private boolean   axisOn = true;
  private boolean   axisLabelsOn = false;
  protected boolean ticLabelsOn = false;
  private String    xAxisLabel = "x-Axis";
  private String    yAxisLabel = "y-Axis";
  private String    graphTitle = "";

  private Dimension currentDimension;
  private boolean   autoRepaint = false;

  private Font      ticFont;
  private Font      titleFont;

  protected boolean   xTicMarks = false;
  protected boolean   yTicMarks = false;
  protected boolean   xGridLines = false;
  protected boolean   yGridLines = false;
  private double      xTicInc = 1.0;
  private double      yTicInc = 1.0;


  /** double buffer for smooth drawing. */
  protected Image     dbIma = null;
  /** double buffers graphics object. */
  protected Graphics  dbG = null;
  /** flag to determine if double buffer is being used. */
  protected boolean   useDoubleBuffer=true;


  /**
  Create a bounded visual Cartesian coordinate system.
  @param minX leftmost value displayed on the x-axis
  @param maxX rightmost value displayed on the x-axis
  @param minY lowest value displayed on the y-axis
  @param maxY highest value displayed on the y-axis
  */
  public Axis(double minX, double maxX, double minY, double maxY)
   {
     super();
     this.minX = minX;
     this.maxX = maxX;
     this.minY = minY;
     this.maxY = maxY;

     init();
   }

  /**
  Create a bounded visual Cartesian coordinate system with a title.
  @param minX leftmost value displayed on the x-axis
  @param maxX rightmost value displayed on the x-axis
  @param minY lowest value displayed on the y-axis
  @param maxY highest value displayed on the y-axis
  @param title the title of the coordinate system
  */
  public Axis(double minX, double maxX, double minY, double maxY, String title)
   {
     super();
     this.minX = minX;
     this.maxX = maxX;
     this.minY = minY;
     this.maxY = maxY;
     this.graphTitle = title;

     init();
   }

  private void init()
   {
     titleFont = new Font("Dialog", Font.BOLD, 10);
     ticFont = new Font("Dialog", Font.BOLD, 10);

     addComponentListener(this);
   }

  /**
  Controls whether the display is refreshed automatically when a visual component of the coordinate system is updated.
  @param b true: refresh display automatically
  */
  public void autoRepaintEnable(boolean b)
   {
     autoRepaint = b;
   }

  public void enableAxis(boolean b)
   {
     axisOn = b; 
   }

  /**
  Controls display of axis labels.
  @param b true: display tic mark labels
  */
  public void enableAxisLabels(boolean b)
   {
     axisLabelsOn = b; 
   }

  /**
  Controls display of grid lines.
  @param x true: display x-axis grid lines
  @param y true: display y-axis grid lines
  */
  public void enableGridLines(boolean x, boolean y)
   {
     xGridLines = x;
     yGridLines = y;
     if(autoRepaint) repaint();
   }

  /**
  Controls display of tic mark labels.
  @param b true: display tic mark labels
  */
  public void enableTicLabels(boolean b)
   {
     ticLabelsOn = b; 
   }

  /**
  Controls display of tic marks.
  @param x true: display x-axis tic marks
  @param y true: display y-axis tic marks
  */
  public void enableTics(boolean x, boolean y)
   {
     xTicMarks = x;
     yTicMarks = y;
     if(autoRepaint) repaint();
   }

  /**
  Draws Cartesian coordinate system.
  */
  public void paint(Graphics g)
   {
     calculateDimensions();
     
     if(useDoubleBuffer)
      {
        draw(dbG);
        g.drawImage(dbIma, 0, 0, Color.black, this);
      }
     else
      {
        draw(g);
      }
   }


  /**
  Enables double buffering for drawing operations.
  */
  public void enableDoubleBuffer(boolean on)
   {
     useDoubleBuffer = on;
   }

  /**
  draws th axis object using specified graphics object.
  */
  protected void draw(Graphics g)
   {
     calculateDimensions();

     Dimension dim = getSize();
        g.setColor(getBackground());
  //   g.clearRect(0, 0, dim.width, dim.height);
     g.fillRect(0, 0, dim.width, dim.height);
     drawTics(g);
     if(titleOn)  drawTitle(g);
     if(axisOn)   drawAxis(g);
   }

  

  /**
  Draws the coordinate system to a new scale.
  @param minX leftmost value displayed on the x-axis
  @param maxX rightmost value displayed on the x-axis
  @param minY lowest value displayed on the y-axis
  @param maxY highest value displayed on the y-axis
  */
  public void rescale(double minX, double maxX, double minY, double maxY)
   {
     this.minX = minX;
     this.maxX = maxX;
     this.minY = minY;
     this.maxY = maxY;

     calculateDimensions();

     if (autoRepaint) repaint();
   }

  /**
  Sets the color of the axis.
  @param c axis color
  */
  public void setAxisColor(Color c)
   {
     axisColor = c;
     if(autoRepaint) repaint();
   }

  /**
  Sets the position of the axis - default is (0,0).
  @param x defines y-axis
  @param y defines x-axis
  */
  public void setAxisPosition(double x, double y)
   {
     xAxisPosition = x;
     yAxisPosition = y;

//     calculateDimensions();
   }

  /**
  Sets the color of the tic marks.
  @param c tic mark color
  */
  public void setTicColor(Color c)
   {
     ticColor = c;
     if(autoRepaint) repaint();
   }

  /**
  Sets the font of the tic labels.
  @param f font of tic mark label
  */
  public void setTicFont(Font f)
   {
     ticFont = f;
   }

  /**
  Sets the distance between tic marks (distance scaled to coordinate system).
  @param xInc distance between x-axis tics
  @param yInc distance between y-axis tics
  */
  public void setTicIncrement(double xInc, double yInc)
   {
     xTicInc = xInc;
     yTicInc = yInc;
     if(autoRepaint) repaint();
   }

  /**
  Sets the coordinate system title.  The title is printed in the upper center of the chart.
  @param title the title of the coordinate system
  */
  public void setTitle(String title)
   {
     this.graphTitle = title;
     if(autoRepaint) repaint();
   }

  public void setTitleColor(Color c)
   {
     titleColor = c;
   }

  /**
  Sets the font of the title.
  @param f font of title
  */
  public void setTitleFont(Font f)
   {
     titleFont = f;
   }

  /**
  Draws the tic marks.
  */
  protected void drawTics(Graphics g)
   {
     double x=0;
     double y=0;
     int start;
     Point axisPoint;
     Point textPoint = new Point(0, 0);
     Point screen;
     int yTicLength;
     int xTicLength;
     Font tempFont;
     ColorPoint firstVisible;
     ColorPoint lastVisible;


     g.setColor(ticColor);
     tempFont = g.getFont();
     g.setFont(ticFont);
     axisPoint = graphToScreen(yAxisPosition, xAxisPosition);

     lastVisible =  screenToGraph(xAxisLength, yAxisLength);
     firstVisible = screenToGraph(0, 0);
     firstVisible.x = (double)((int)(firstVisible.x / xTicInc)) * xTicInc;
     firstVisible.y = (double)((int)(firstVisible.y / yTicInc)) * yTicInc;

     if(xTicMarks == true || xGridLines == true)
      {
       if(xGridLines == true)
        {
         start = 0;
         yTicLength = yAxisLength;
        }
       else
        {
         yTicLength = (int)(yAxisLength *.02);
         start = axisPoint.y - (yTicLength/2);
        } 

       textPoint.y = axisPoint.y - 2;
       for(x = firstVisible.x; x <= lastVisible.x; x += xTicInc)
        {
          screen = graphToScreen(x, y);
          textPoint.x = screen.x + 2;
          g.drawLine(screen.x, start, screen.x, start + yTicLength);
          if(ticLabelsOn)
             g.drawString(new Double(x).toString(), textPoint.x, textPoint.y);
        }
      }

     if(yTicMarks == true || yGridLines == true)
      {
       if(yGridLines == true)
        {
          start = 0;
          xTicLength = xAxisLength;
        }
       else
        {
          xTicLength = (int)(xAxisLength *.02);
          start = axisPoint.x - (xTicLength/2);
        }
       textPoint.x = axisPoint.x + 2;
       for(y = firstVisible.y; y >= lastVisible.y; y -= yTicInc)
        {
          screen = graphToScreen(x, y);
          textPoint.y = screen.y - 2;
          g.drawLine(start, screen.y, start + xTicLength, screen.y);
          if(ticLabelsOn)
             g.drawString(new Double(y).toString(), textPoint.x, textPoint.y);
        }
      }
     g.setFont(tempFont);
   }

  /**
  Scales a data coordinate into a display coordinate
  @param inX x-coordinate of point to be scaled
  @param inY y-coordinate of point to be scaled
  @return Point scaled to the current scale of the coordinate system
  */
  public Point graphToScreen(double inX, double inY)
   {
     int x, y;

     calculateDimensions();

     x = (int)(inX * scaleX + originY);
     y = originX - (int)(inY * scaleY);

     return new Point(x, y);
   }

  /**
  Scales a display coordinate into a data coordinate
  @param inX x-coordinate of point to be scaled
  @param inY y-coordinate of point to be scaled
  @return Point scaled to the current scale of the coordinate system
  */
  public ColorPoint screenToGraph(int inX, int inY)
   {
     double x, y;

     calculateDimensions();

     x = (inX - originY) / scaleX;
     y = (originX - inY) / scaleY;

     return new ColorPoint(x, y);
   }


  /**
  Calculates current scaling attributes of the graph.
  Whenever the chart is resized this method should be called.
  */
  private void calculateDimensions()
   {
     double lengthX;
     double lengthY;
     Dimension dim;
     FontMetrics fm;

     currentDimension = getSize();
     dim = getSize();

     fm = this.getFontMetrics(this.getFont());

     xAxisLength = dim.width;
     yAxisLength = dim.height;

     lengthX = maxX - minX;
     lengthY = maxY - minY;
     if(lengthX < 0) lengthX = - lengthX;
     if(lengthY < 0) lengthY = - lengthY;

     scaleX = xAxisLength / lengthX;
     scaleY = yAxisLength / lengthY;

     originX = dim.height + (int)(scaleY * minY);
     originY = 0 - (int)(scaleX * minX);
   }

  /**
  Draws the x and y axes.
  */
  private void drawAxis(Graphics g)
  {
     Point axisPoint;

     axisPoint = graphToScreen(yAxisPosition, xAxisPosition);

     g.setColor(axisColor);

     g.drawLine(0, axisPoint.y, xAxisLength, axisPoint.y);
     g.drawLine(axisPoint.x, 0, axisPoint.x, yAxisLength);
   }

  /**
  Draws the coordinate system title.
  */
  private void drawTitle(Graphics g)
   {
     Dimension dim;
     Font tempFont;
     FontMetrics fm;
     int width;
     int centerX;

     g.setColor(titleColor);
     dim = this.getSize();

     tempFont = g.getFont();
     g.setFont(titleFont);

     fm = this.getFontMetrics(titleFont);
     width = fm.stringWidth(this.graphTitle);

     centerX = (dim.width - width) / 2;

     g.drawString(this.graphTitle, centerX, fm.getHeight());

     g.setFont(tempFont);
   }

  public void componentHidden(ComponentEvent cE)
   {
   }

  public void componentMoved(ComponentEvent cE)
   {
   }

  /**
  When the component is created or resized a new double buffer is
  allocated for smooth drawing operations.
  */
  public void componentResized(ComponentEvent cE)
   {
     Dimension dim = getSize();
     calculateDimensions();

     dbIma = this.createImage(dim.width, dim.height);
     dbG = dbIma.getGraphics();
   }

  public void componentShown(ComponentEvent cE)
   {
   }
}
