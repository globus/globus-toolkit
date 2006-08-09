<?xml version="1.0"?>
<xsl:stylesheet version='1.0' xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text" indent="no" encoding="US-ASCII"/>

<xsl:template match="/">
   <xsl:for-each select="report/entry">
	<xsl:number value="position()"/>
	<xsl:text> </xsl:text>
        <xsl:for-each select="scheduler">
		<xsl:value-of select="jobs"/>
		<xsl:text> </xsl:text>
		<xsl:value-of select="unique-domains"/>
		<xsl:text> </xsl:text>
		<xsl:value-of select="unique-ip"/>
		<xsl:text> </xsl:text>
	</xsl:for-each>
	<xsl:text>
</xsl:text>
</xsl:for-each>
</xsl:template>
</xsl:stylesheet>