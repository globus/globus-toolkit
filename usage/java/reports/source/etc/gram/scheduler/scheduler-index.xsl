<?xml version="1.0"?>
<xsl:stylesheet version='1.0' xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="html" indent="yes" encoding="UTF-8"/>

<xsl:template match="/">
<html>
<head>
   <title>WS Gram Scheduler, Host and Domain Reports</title>
</head>
<body>
<h3>WS Gram Scheduler, Host and Domain Reports</h3>

[<a href="GRAMSchedulerReport.xml">raw data</a>]

<ul>
        <xsl:for-each select="report/entry[1]/scheduler">
            <li>
                <a href="{concat(name, '.png')}">
                    <xsl:value-of select="name"/>
                    <xsl:text> Jobs, Hosts, and Domains</xsl:text>
                </a>
            </li>
	</xsl:for-each>
</ul>

</body>
</html>
</xsl:template>
</xsl:stylesheet>
