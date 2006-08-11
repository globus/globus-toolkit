<?xml version="1.0"?>
<xsl:stylesheet
   version='1.0'
   xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
>

<xsl:output method="text" indent="no" encoding="US-ASCII"/>

<xsl:template match="/"> 
<xsl:text>set terminal png size 1024,768
set output "event.png"
set title "Container Event Report (</xsl:text><xsl:value-of select="container-event-report/start-date"/><xsl:text> to </xsl:text><xsl:value-of select="container-event-report/end-date"/><xsl:text>)"

my_width=0.2

set style line 1 lt 1 lw 50
set style fill solid border -1
set xtics 2
set boxwidth my_width
set xtic nomirror rotate
# set logscale y
set bmargin 7
</xsl:text>

 <xsl:text>set xtics (</xsl:text>
 <xsl:for-each select="container-event-report/unmatched-events/slot">
      <xsl:text>&quot;</xsl:text>
      <xsl:value-of select="time"/>
      <xsl:text>&quot; </xsl:text><xsl:number value="position()"/>
      <xsl:if test="not(position() = last())"><xsl:text>, </xsl:text></xsl:if>
 </xsl:for-each>
 <xsl:text>)</xsl:text>

<xsl:text>
plot 'event.data' using ($1-my_width/2):2 title "# of unmatched starts" with boxes fs pattern 1,'event.data' using ($1+my_width/2):3 title "# of unmatched stops" with boxes fs pattern 2
</xsl:text>

</xsl:template>

</xsl:stylesheet>
