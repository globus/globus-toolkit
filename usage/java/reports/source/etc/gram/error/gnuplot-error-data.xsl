<?xml version="1.0"?>
<xsl:stylesheet version='1.0' xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text" indent="no" encoding="US-ASCII"/>

<xsl:template match="/">
  <xsl:for-each select="report/histogram[output='percentfailedhistogram']/entry">
      <xsl:number value="position()"/>
      <xsl:text> </xsl:text>
      <xsl:value-of select="item[name='GT2 Error Code']/single-value"/>
      <xsl:text> </xsl:text>
      <xsl:value-of select="item[name='Fault Class']/single-value"/>
      <xsl:text> </xsl:text>
<xsl:text>
</xsl:text>
  </xsl:for-each>
</xsl:template>

</xsl:stylesheet>
