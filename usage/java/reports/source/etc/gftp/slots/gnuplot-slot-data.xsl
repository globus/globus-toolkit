<?xml version="1.0"?>
<xsl:stylesheet version='1.0' xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text" indent="no" encoding="US-ASCII"/>

<xsl:template match="/">
   <xsl:for-each select="report/histogram">
	<xsl:text>0 0
</xsl:text>
	<xsl:for-each select="slots">
	<xsl:for-each select="item">
        	<xsl:sort select="single-value" data-type="number" order="descending"/>
        	<xsl:number value="position()"/>
        	<xsl:text> </xsl:text>
                <xsl:value-of select="single-value"/>
                <xsl:text> 
</xsl:text>
        </xsl:for-each>
	</xsl:for-each>
<xsl:text>


</xsl:text>
</xsl:for-each>
</xsl:template>
</xsl:stylesheet>