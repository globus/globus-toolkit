<?xml version="1.0"?>
<xsl:stylesheet
   version='1.0'
   xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
>

<xsl:output method="text" indent="no" encoding="US-ASCII"/>

<xsl:template match="/"> 
  <xsl:for-each select="combined-rftusagediff-report/slot">
      <xsl:number value="position()"/>
      <xsl:text> </xsl:text>
      <xsl:value-of select="count"/>
<xsl:text>
</xsl:text>
  </xsl:for-each>
</xsl:template>

</xsl:stylesheet>
