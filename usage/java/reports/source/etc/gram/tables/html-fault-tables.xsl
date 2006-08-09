<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
        <html>
        <body>
         <h2>Ordered Fault Classes</h2>
        <table border="1">
<xsl:for-each select="report/histogram">
	<xsl:if test="output='faulthistogram'">
	<xsl:for-each select="entry">
       <tr bgcolor="#9acd32">
        <th><xsl:value-of select="start-date"/> - <xsl:value-of select="end-date"/></th>
</tr>
<xsl:for-each select="item">
	<xsl:sort select="single-value" order="descending" data-type="number" />
	<xsl:if test="not(single-value='0')">
        <tr>
            <td><xsl:value-of select="name"/> - <xsl:value-of select="single-value"/></td>
          </tr>
	</xsl:if>
</xsl:for-each>
</xsl:for-each>
</xsl:if>
</xsl:for-each>
</table>
</body>
</html>
</xsl:template>
</xsl:stylesheet>
