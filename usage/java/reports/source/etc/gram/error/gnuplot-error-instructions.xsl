<?xml version="1.0"?>
<xsl:stylesheet
   version='1.0'
   xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
>

<xsl:output method="text" indent="no" encoding="US-ASCII"/>

<xsl:template match="/">
<xsl:text>set terminal png size 1024,768
set output "error.png"
set title "Percentage of Jobs With Error or Fault Codes"

my_width=0.3

set style line 1 lt 1 lw 50
set style fill solid border -1
set xtics 2
set boxwidth my_width
set xtic nomirror rotate
set bmargin 7
set autoscale ymax
set autoscale y2max
set y2tics
set key below
set ylabel "% of jobs with fault class"
set y2label "% of jobs with gt2 error code"
</xsl:text>

 <xsl:text>set xtics (</xsl:text>
 <xsl:for-each select="report/entry">
      <xsl:text>&quot;</xsl:text>
      <xsl:value-of select="start-date"/>
      <xsl:text>&quot; </xsl:text><xsl:number value="position()"/>
      <xsl:if test="not(position() = last())"><xsl:text>, </xsl:text></xsl:if>
 </xsl:for-each>
 <xsl:text>)</xsl:text>

<xsl:text>
plot 'error.data' using 1:3 title "% fault-class-left axis" with boxes fs pattern 1, 'error.data' using ($1+my_width):2 axis x1y2 title "% gt2 codes-right axis" with boxes fs pattern 2
</xsl:text>

</xsl:template>

</xsl:stylesheet>