package org.globus.gridftp;

import java.awt.*; 

public class ColorPoint
{
  public double x;
  public double y;
  public Color  color;

  public ColorPoint(double x, double y, Color color)
   {
     this.x = x;
     this.y = y;
     this.color = color;
   }

  public ColorPoint(float x, float y, Color color)
   {
     this.x = (double)x;
     this.y = (double)y;
     this.color = color;
   }

  public ColorPoint(int x, int y, Color color)
   {
     this.x = (double)x;
     this.y = (double)y;
     this.color = color;
   }

  public ColorPoint(double x, double y)
   {
     this.x = x;
     this.y = y;
   }

  public ColorPoint(float x, float y)
   {
     this.x = (double)x;
     this.y = (double)y;
   }

  public ColorPoint(int x, int y)
   {
     this.x = (double)x;
     this.y = (double)y;
   }
}
