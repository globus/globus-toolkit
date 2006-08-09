<?xml version="1.0"?>
<xsl:stylesheet
   version='1.0'
   xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
>

<xsl:output method="text" indent="no" encoding="US-ASCII"/>

<xsl:template match="/">
<xsl:text>set terminal png size 1024,768
set output "jobtype.png"
set title "Percentage of Jobs Submitted as Each Job Type"

my_width=0.15

set style line 1 lt 1 lw 50
set style fill solid border -1
set xtics 2
set boxwidth my_width
set xtic nomirror rotate
set bmargin 7
set yrange[0:100]
set y2range[0:5]
set autoscale y2
set y2tics
set ylabel "% of Jobs submitted as Multiple"
set y2label "% of Jobs submitted as MPI, Condor, or Single"
set key below

</xsl:text>

<xsl:text>set xtics (</xsl:text>
 <xsl:for-each select="job-type-report/entry">
      <xsl:text>&quot;</xsl:text>
      <xsl:value-of select="start-date"/>
      <xsl:text>&quot; </xsl:text><xsl:number value="position()"/>
      <xsl:if test="not(position() = last())"><xsl:text>, </xsl:text></xsl:if>
 </xsl:for-each>
 <xsl:text>)</xsl:text>

<xsl:text>
plot 'jobtype.data' using 1:3 axis x1y1 title "Multiple-left axis" with boxes fs pattern 1,'jobtype.data' using ($1+my_width+.1):2 title "Single-right axis" with boxes fs pattern 2,'jobtype.data' using ($1+2*my_width+.1):4 axis x1y2 title "Condor-right axis" with boxes fs pattern 3,'jobtype.data' using ($1+3*my_width+.1):5 axis x1y2  title "MPI-right axis" with boxes fs pattern 4
</xsl:text>

</xsl:template>
</xsl:stylesheet>