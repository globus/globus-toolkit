<?xml version="1.0"?>
<xsl:stylesheet version='1.0' xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text" indent="no" encoding="US-ASCII"/>

<xsl:template match="/">
   <xsl:for-each select="report/histogram[output='jobhistogram']/entry">
        <xsl:variable name="start-date" select="start-date"/>
        <xsl:variable name="end-date" select="end-date"/>

	<xsl:number value="position()"/>
	<xsl:text> </xsl:text>
        <xsl:for-each select="item[not(name = ' other ')]|item/sub-item">
                <xsl:variable name="unique-domains">
                    <xsl:apply-templates select="//report/histogram" mode="unique-domains">
                        <xsl:with-param name="scheduler" select="name"/>
                        <xsl:with-param name="start-date" select="$start-date"/>
                        <xsl:with-param name="end-date" select="$end-date"/>
                    </xsl:apply-templates>
                </xsl:variable>
                <xsl:variable name="unique-ips">
                    <xsl:apply-templates select="//report/histogram" mode="unique-ips">
                        <xsl:with-param name="scheduler" select="name"/>
                        <xsl:with-param name="start-date" select="$start-date"/>
                        <xsl:with-param name="end-date" select="$end-date"/>
                    </xsl:apply-templates>
                </xsl:variable>
                        
		<xsl:value-of select="single-value"/>
		<xsl:text> </xsl:text>
		<xsl:value-of select="$unique-domains"/>
		<xsl:text> </xsl:text>
		<xsl:value-of select="$unique-ips"/>
		<xsl:text> </xsl:text>
	</xsl:for-each>
	<xsl:text>
</xsl:text>
</xsl:for-each>
</xsl:template>

<xsl:template match="histogram" mode="unique-domains">
    <xsl:param name="scheduler"/>
    <xsl:param name="start-date"/>
    <xsl:param name="end-date"/>

    <xsl:if test="output = concat($scheduler, 'domainhistogram')">
        <xsl:apply-templates select="entry" mode="count-items">
            <xsl:with-param name="start-date" select="$start-date"/>
            <xsl:with-param name="end-date" select="$end-date"/>
        </xsl:apply-templates>
    </xsl:if>
</xsl:template>

<xsl:template match="histogram" mode="unique-ips">
    <xsl:param name="scheduler"/>
    <xsl:param name="start-date"/>
    <xsl:param name="end-date"/>

    <xsl:if test="output = concat($scheduler, 'iphistogram')">
        <xsl:apply-templates select="entry" mode="count-items">
            <xsl:with-param name="start-date" select="$start-date"/>
            <xsl:with-param name="end-date" select="$end-date"/>
        </xsl:apply-templates>
    </xsl:if>
</xsl:template>

<xsl:template match="entry" mode="count-items">
    <xsl:param name="start-date"/>
    <xsl:param name="end-date"/>

    <xsl:if test="start-date = $start-date and end-date = $end-date">
        <xsl:value-of select="count(
                item[not(name = ' other ') and not(single-value = 0.0)] |
                item/sub-item[not(single-value = 0.0)])"/>
    </xsl:if>
</xsl:template>
</xsl:stylesheet>
