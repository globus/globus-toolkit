<?xml version="1.0"?>
<xsl:stylesheet version='1.0' xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text" indent="no" encoding="US-ASCII"/>
<xsl:template match="/">

<xsl:text>
set terminal png size 1024,768
my_width=0.25

set yrange[0:100]
set autoscale ymax
set style line 1 lt 1 lw 50
set xtics 2
set style fill pattern border
set boxwidth my_width
set style fill solid border -1
unset xtics
set xtics nomirror
set bmargin 7
set key outside
</xsl:text>

<xsl:for-each select="report/histogram">
<xsl:text>
my_index=</xsl:text>
<xsl:number value="position()"/>
<xsl:text>-1
set title "</xsl:text>
<xsl:value-of select="title"/>
<xsl:text>"
set ylabel "</xsl:text><xsl:value-of select="axis"/>
<xsl:text>"
set output "</xsl:text>
<xsl:value-of select="output"/>
<xsl:text>.png"
</xsl:text>
<xsl:text>set xtics (</xsl:text>
 <xsl:for-each select="entry">
      <xsl:text>&quot;</xsl:text>
      <xsl:value-of select="start-date"/>
      <xsl:text>&quot; </xsl:text><xsl:number value="position()"/>
      <xsl:if test="not(position() = last())"><xsl:text>, </xsl:text></xsl:if>
 </xsl:for-each>
<xsl:text>)</xsl:text>
<xsl:for-each select="entry">
<xsl:if test="position() = 1">
<xsl:text>
plot </xsl:text>
<xsl:for-each select="item">
<xsl:text>'histograms.data' index my_index using 1:</xsl:text><xsl:number value="position()"/>
<xsl:text>+1 title "</xsl:text><xsl:value-of select="name"/><xsl:text>" with boxes fs pattern </xsl:text><xsl:number value="position()"/>
<xsl:if test="not(position() = last())"><xsl:text>, </xsl:text></xsl:if>
</xsl:for-each>
</xsl:if>
</xsl:for-each>
</xsl:for-each>
</xsl:template>
</xsl:stylesheet>