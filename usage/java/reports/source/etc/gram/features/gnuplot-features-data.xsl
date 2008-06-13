<?xml version="1.0"?>
<xsl:stylesheet version='1.0' xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text" indent="no" encoding="US-ASCII"/>

<xsl:template match="/">
  <xsl:for-each select="features-report/histogram/entry">
      <xsl:number value="position()"/>
      <xsl:text> </xsl:text>
      <xsl:value-of select="item[name='job-endpoint-used']/single-value"/>
      <xsl:text> </xsl:text>
      <xsl:value-of select="item[name='file-stage-in-used']/single-value"/>
      <xsl:text> </xsl:text>
      <xsl:value-of select="item[name='file-stage-out-used']/single-value"/>
      <xsl:text> </xsl:text>
      <xsl:value-of select="item[name='file-clean-up-used']/single-value"/>
	<xsl:text> </xsl:text>
	<xsl:value-of select="item[name='clean-up-hold-used']/single-value"/>
	<xsl:text> </xsl:text>	
<xsl:text>
</xsl:text>
  </xsl:for-each>
</xsl:template>

</xsl:stylesheet>
