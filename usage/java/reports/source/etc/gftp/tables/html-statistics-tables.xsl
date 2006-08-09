<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
        <html>
        <body>
         <h2>Bytes Transferred Statistics</h2>
        <table border="1">
       <tr bgcolor="#9acd32">
        <th>Mean of Number of Bytes Transfered</th>
</tr>
<xsl:for-each select="report/entry">
        <tr>
            <td><xsl:value-of select="start-date"/> - <xsl:value-of select="byte/mean"/> bytes</td>
          </tr>
</xsl:for-each>
</table>
<table border="1">
       <tr bgcolor="#9acd32">
        <th>Standard Deviation of Number of Bytes Transfered</th>
</tr>
<xsl:for-each select="report/entry">
        <tr>
            <td><xsl:value-of select="start-date"/> - <xsl:value-of select="byte/standard-deviation"/> bytes</td>
          </tr>
</xsl:for-each>
</table>
<table border="1">
       <tr bgcolor="#9acd32">
        <th>95% Confidence Interval for Number of Bytes Transfered</th>
</tr>
<xsl:for-each select="report/entry">
        <tr>
            <td><xsl:value-of select="start-date"/> : <xsl:value-of select="byte/low-CI"/> bytes - <xsl:value-of select="byte/high-CI"/> bytes</td>
          </tr>
</xsl:for-each>
</table>

         <h2>Block Size Statistics</h2>
        <table border="1">
       <tr bgcolor="#9acd32">
        <th>Mean of Block Size</th>
</tr>
<xsl:for-each select="report/entry">
        <tr>
            <td><xsl:value-of select="start-date"/> - <xsl:value-of select="block/mean"/> bytes</td>
          </tr>
</xsl:for-each>
</table>
<table border="1">
       <tr bgcolor="#9acd32">
        <th>Standard Deviation of Block Size</th>
</tr>
<xsl:for-each select="report/entry">
        <tr>
            <td><xsl:value-of select="start-date"/> - <xsl:value-of select="block/standard-deviation"/> bytes</td>
          </tr>
</xsl:for-each>
</table>
<table border="1">
       <tr bgcolor="#9acd32">
        <th>95% Confidence Interval for Block Size</th>
</tr>
<xsl:for-each select="report/entry">
        <tr>
            <td><xsl:value-of select="start-date"/> : <xsl:value-of select="block/low-CI"/> bytes - <xsl:value-of select="block/high-CI"/> bytes</td>
          </tr>
</xsl:for-each>
</table>
         <h2>TCP Buffer Size</h2>
        <table border="1">
       <tr bgcolor="#9acd32">
        <th>Mean of TCP Buffer Size</th>
</tr>
<xsl:for-each select="report/entry">
        <tr>
            <td><xsl:value-of select="start-date"/> - <xsl:value-of select="buffer/mean"/> bytes</td>
          </tr>
</xsl:for-each>
</table>
<table border="1">
       <tr bgcolor="#9acd32">
        <th>Standard Deviation of TCP Buffer Size</th>
</tr>
<xsl:for-each select="report/entry">
        <tr>
            <td><xsl:value-of select="start-date"/> - <xsl:value-of select="buffer/standard-deviation"/> bytes</td>
          </tr>
</xsl:for-each>
</table>
<table border="1">
       <tr bgcolor="#9acd32">
        <th>95% Confidence Interval for TCP Buffer Size</th>
</tr>
<xsl:for-each select="report/entry">
        <tr>
            <td><xsl:value-of select="start-date"/> : <xsl:value-of select="buffer/low-CI"/> bytes - <xsl:value-of select="buffer/high-CI"/> bytes</td>
          </tr>
</xsl:for-each>
</table>



</body>
</html>
</xsl:template>
</xsl:stylesheet>
