<?xml version="1.0"?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    exclude-result-prefixes="exsl"
    extension-element-prefixes="exsl"
    version="1.0"
    >

    <xsl:output
            method="xml"
            doctype-system="http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd"
            doctype-public="-//OASIS//DTD DocBook XML V4.4//EN"
            indent="yes"/>
    

    <xsl:param name="release-version" select="'5.2.1'"/>
    <xsl:variable name="branch-version" select="
            concat(
                substring-before($release-version, '.'),
                '.',
                substring-before(
                    substring-after($release-version, '.'),
                    '.'))"/>
    <xsl:variable name="advisories-page" select="
            concat(
                'http://www.globus.org/toolkit/advisories.html?version=',
                $branch-version)"/>
    <xsl:param name="output-dir" select="frags"/>
    

    <xsl:template match="*">
        <xsl:element name="{local-name()}">
            <xsl:apply-templates select="@*"/>
            <xsl:apply-templates select="*"/>
            <xsl:apply-templates select="text()"/>
        </xsl:element>
    </xsl:template>

    <xsl:template match="@*">
        <xsl:copy-of select="."/>
    </xsl:template>

    <xsl:template match="text()">
        <xsl:value-of select="."/>
    </xsl:template>

    <xsl:template match="simpara">
        <xsl:element name="simpara">
            <xsl:apply-templates select="*"/>
            <xsl:apply-templates select="text()"/>
            <xsl:apply-templates select="ulink" mode="show-fixes"/>
        </xsl:element>
    </xsl:template>

    <xsl:template match="ulink" mode="show-fixes">
        <xsl:variable name="issue-number" select="text()"/>
        <xsl:variable name="fixes">
            <xsl:apply-templates select="document(concat($release-version, '/advisories.xml'))/advisories/item[
                    version = $release-version and
                    (
                        contains(description/text(), concat($issue-number, ':')) or
                        contains(description/text(), concat('(', $issue-number, ')'))
                    )][1]"/>
        </xsl:variable>

        <xsl:if test="$fixes != ''">
            <xsl:text>. [fixed: </xsl:text>
            <xsl:copy-of select="$fixes"/>
            <xsl:apply-templates select="document(concat($release-version, '/advisories.xml'))/advisories/item[
                    version = $release-version and
                    (contains(description/text(), concat($issue-number, ':'))
                     or contains(description/text(), concat('(', $issue-number, ')')))][position() > 1]">
                <xsl:with-param name="prefix" select="', '"/>
            </xsl:apply-templates>
            <xsl:text>]</xsl:text>
        </xsl:if>

    </xsl:template>

    <xsl:template match="item">
        <xsl:param name="prefix"/>
        <xsl:variable name="fixname" select="substring-before(pkg, '.tar.gz')"/>

        <xsl:value-of select="$prefix"/>
        <xsl:element name="ulink">
            <xsl:attribute name="url">
                <xsl:value-of select="concat($advisories-page, '#', pkg)"/>
            </xsl:attribute>
            <xsl:value-of select="$fixname"/>
        </xsl:element>
    </xsl:template>

</xsl:stylesheet>
