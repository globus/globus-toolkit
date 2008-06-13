<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">


<xsl:template match="/">
	<html>
	<body>
	 <h2>Ordered GT2 Error Codes</h2>
	<table border="1">
<xsl:for-each select="report/histogram">
<xsl:if test="output='gt2histogram'">
<xsl:for-each select="entry">
<tr bgcolor="#9acd32">
	<th colspan="2"><xsl:value-of select="start-date"/> - <xsl:value-of select="end-date"/></th>
</tr>

<xsl:for-each select="item">
	<xsl:sort select="single-value" data-type="number" order="descending"/>
	<xsl:if test="not(single-value='0')">
	<tr>
		<td>Code: <xsl:value-of select="name"/></td>
                <td><xsl:value-of select="single-value"/></td>
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

