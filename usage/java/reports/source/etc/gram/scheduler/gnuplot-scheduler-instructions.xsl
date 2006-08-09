<?xml version="1.0"?>
<xsl:stylesheet version='1.0' xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="text" indent="no" encoding="US-ASCII"/>

<xsl:template match="/">
<xsl:text>set terminal png size 1024,768
my_width=0.15

set yrange[0:100]
set y2range[0:100]
set autoscale ymax
set autoscale y2max
set style line 1 lt 1 lw 50
set style fill solid border -1
set xtics 2
set boxwidth my_width
set xtic nomirror rotate
set bmargin 7
set key below right


</xsl:text>

<xsl:text>set xtics (</xsl:text>
 <xsl:for-each select="report/entry">
      <xsl:text>&quot;</xsl:text>
      <xsl:value-of select="start-date"/>
      <xsl:text>&quot; </xsl:text><xsl:number value="position()"/>
      <xsl:if test="not(position() = last())"><xsl:text>, </xsl:text></xsl:if>
 </xsl:for-each>
<xsl:text>)
</xsl:text>

<xsl:for-each select="report/entry/scheduler">
	<xsl:text>set output "</xsl:text> 
	<xsl:value-of select="name"/>
	<xsl:text>.png"
set title " Graph of Jobs, Hosts, and Domains for </xsl:text>
	<xsl:value-of select="name"/>
	<xsl:text>"
set y2tics 
plot 'scheduler.data' using 1:3*(</xsl:text>
	<xsl:value-of select="index"/>
	<xsl:text>-1)+2 title "Jobs Submitted to </xsl:text>
	<xsl:value-of select="name"/>
	<xsl:text> Services- left axis" with boxes fs pattern 1,'scheduler.data' using ($1+2*my_width):3*(</xsl:text>
        <xsl:value-of select="index"/>
        <xsl:text>-1)+3 axis x1y2 title "Number of Unique Domains Hosting </xsl:text>
	<xsl:value-of select="name"/>
	<xsl:text> services-right axis" with boxes fs pattern 2,'scheduler.data' using ($1+3*my_width):3*(</xsl:text>
        <xsl:value-of select="index"/>
        <xsl:text>-1)+4 axis x1y2 title "Number of Unique Service Hosts Using </xsl:text>
	<xsl:value-of select="name"/>
	<xsl:text>-right axis" with boxes fs pattern 3
</xsl:text>
</xsl:for-each>
</xsl:template>
</xsl:stylesheet>