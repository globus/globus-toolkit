<?xml version="1.0"?>
<xsl:stylesheet version='1.0' xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text" indent="no" encoding="US-ASCII"/>

<xsl:template match="/"> 
  <xsl:for-each select="container-report/entry">
      <xsl:number value="position()"/>
      <xsl:text> </xsl:text>
      <xsl:value-of select="all/services"/>
      <xsl:text> </xsl:text>
      <xsl:value-of select="standalone/services"/>
      <xsl:text> </xsl:text>
      <xsl:value-of select="servlet/services"/>
      <xsl:text>
</xsl:text>
  </xsl:for-each>
</xsl:template>

</xsl:stylesheet>
