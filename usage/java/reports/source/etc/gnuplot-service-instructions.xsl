<?xml version="1.0"?>
<xsl:stylesheet
   version='1.0'
   xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
>

<xsl:output method="text" indent="no" encoding="US-ASCII"/>

<xsl:template match="/"> 
<xsl:text>set terminal png size 2048,1536
set output "service.png"
set title "Service Report"

my_width=0.2

set style line 1 lt 1 lw 50
set style fill solid border -1
set xtics 2
set boxwidth my_width
set xtic nomirror rotate

</xsl:text>

 <xsl:text>set xtics (</xsl:text>
 <xsl:for-each select="service-report/entry">
      <xsl:text>&quot;</xsl:text>
      <xsl:value-of select="service-name"/>
      <xsl:text>&quot; </xsl:text><xsl:number value="position()"/>
      <xsl:if test="not(position() = last())"><xsl:text>, </xsl:text></xsl:if>
 </xsl:for-each>
 <xsl:text>)</xsl:text>

<xsl:text>
plot 'service.data.gnuplot' using 1:2 title "standalone container" with boxes fs pattern 1,'service.data.gnuplot' using ($1+my_width):3 title "servlet container" with boxes fs pattern 2
</xsl:text>

</xsl:template>

</xsl:stylesheet>
