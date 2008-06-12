<?xml version="1.0"?>
<xsl:stylesheet
   version='1.0'
   xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
>

<xsl:output method="text" indent="no" encoding="US-ASCII"/>
<xsl:variable name="report" select="//histogram/output"/>
<xsl:variable name="report-component" select="
        substring-before(substring-after($report, '-'), '-')"/>

<xsl:template match="/"> 
<xsl:text>set terminal png size 1024,768
set output "</xsl:text>
<xsl:value-of select="$report-component"/>
<xsl:text>histogram.png"
set title "</xsl:text>
<xsl:value-of select="*/histogram/title"/>
<xsl:text>"

my_width=0.2

set style line 1 lt 1 lw 50
set style fill solid border -1
set xtics 2
set boxwidth my_width
set xtic nomirror rotate
set logscale y
set bmargin 7
</xsl:text>

 <xsl:text>set xtics (</xsl:text>
 <xsl:for-each select="//slots/item">
      <xsl:sort select="substring-before(name, ' ')" data-type="number"/>
      <xsl:text>&quot;</xsl:text>
      <xsl:value-of select="name"/>
      <xsl:text>&quot; </xsl:text><xsl:number value="position()"/>
      <xsl:if test="not(position() = last())"><xsl:text>, </xsl:text></xsl:if>
 </xsl:for-each>
 <xsl:text>)</xsl:text>

<xsl:text>
plot '</xsl:text>
<xsl:value-of select="$report-component"/>
<xsl:text>.data' using 1:2 title "# of containers" with boxes fs pattern 1
</xsl:text>

</xsl:template>

</xsl:stylesheet>
