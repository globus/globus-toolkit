<?xml version="1.0"?>
<xsl:stylesheet
   version='1.0'
   xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
>

<xsl:output method="text" indent="no" encoding="US-ASCII"/>

<xsl:template match="/">
<xsl:text>set terminal png size 1024,768
set output "features.png"
set title "</xsl:text>
<xsl:value-of select="features-report/histogram/title"/>
<xsl:text>"

my_width=0.15

set style line 1 lt 1 lw 50
set style fill solid border -1
set xtics 2
set boxwidth my_width
set xtic nomirror rotate
set bmargin 7
set yrange [0:100]
set y2range [0:100]
set autoscale y2max
set key below
</xsl:text>

 <xsl:text>set xtics (</xsl:text>
 <xsl:for-each select="features-report/histogram/entry">
      <xsl:text>&quot;</xsl:text>
      <xsl:value-of select="start-date"/>
      <xsl:text>&quot; </xsl:text><xsl:number value="position()"/>
      <xsl:if test="not(position() = last())"><xsl:text>, </xsl:text></xsl:if>
 </xsl:for-each>
 <xsl:text>)</xsl:text>

<xsl:text>
plot 'features.data' using 1:2 title "job credential" with boxes fs pattern 1,'features.data' using ($1+my_width):3 title "stage-in" with boxes fs pattern 2,'features.data' using ($1+2*my_width):4 title "stage-out" with boxes fs pattern 3,'features.data' using ($1+3*my_width):5 title "file-clean-up" with boxes fs pattern 4,'features.data' using ($1+4*my_width):6 title "clean-up-hold" with boxes fs pattern 5
</xsl:text>

</xsl:template>

</xsl:stylesheet>
