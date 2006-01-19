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
