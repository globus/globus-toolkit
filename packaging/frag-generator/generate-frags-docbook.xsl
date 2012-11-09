<?xml version="1.0"?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    xmlns:driver="http://www.globus.org/generate-frags-driver"
    exclude-result-prefixes="exsl driver"
    extension-element-prefixes="exsl"
    version="1.0"
    >

    <xsl:import href="generate-frags-driver.xsl"/>
    <xsl:param name="release-version" select="'GT 5.2.1'"/>
    <xsl:param name="output-dir" select="frags"/>

    <xsl:template match="driver:frag" mode="output">
        <xsl:param name="doc-url"/>
        <xsl:param name="doc-package-name"/>
        <xsl:param name="doc-package-prefix"/>
        <xsl:param name="doc-package-nicename"/>

        <xsl:message>Generating <xsl:value-of select="@name"/> frag for <xsl:value-of select="$doc-package-name"/></xsl:message>

        <exsl:document
            method="xml"
            href="{$output-dir}/{$doc-package-name}_{@name}_Frag.xml"
            doctype-system="http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd"
            doctype-public="-//OASIS//DTD DocBook XML V4.4//EN"
            indent="yes"
        >
            <xsl:variable name="package-nicename">
                <xsl:choose>
                    <xsl:when test="$doc-package-nicename != ''">
                        <xsl:value-of select="$doc-package-nicename"/>
                    </xsl:when>
                    <xsl:otherwise>
                        <xsl:call-template name="replace">
                            <xsl:with-param name="str" select="$doc-package-name"/>
                            <xsl:with-param name="old" select="'_'"/>
                            <xsl:with-param name="new" select="' '"/>
                        </xsl:call-template>
                    </xsl:otherwise>
                </xsl:choose>
            </xsl:variable>
            <section id="{$doc-package-prefix}-{@suffix}">
            <title><xsl:value-of select="concat(@title, $package-nicename)"/></title>

            <xsl:if test="driver:type[2]">
                <xsl:for-each select="driver:type">
                    <xsl:variable name="bug-type" select="."/>
                    <xsl:variable name="resolution" select="@resolution"/>
                    <section><title><xsl:value-of select="concat(., 's: ', $package-nicename)"/></title>
                        <xsl:apply-templates select="document($doc-url)/rss">
                            <xsl:with-param name="doc-package-name" select="$doc-package-name"/>
                            <xsl:with-param name="components" select="key(packages, $doc-package-name)/driver:component"/>
                            <xsl:with-param name="bug-type" select="$bug-type"/>
                            <xsl:with-param name="resolution" select="$resolution"/>
                        </xsl:apply-templates>
                    </section>
                </xsl:for-each>
            </xsl:if>
            <xsl:if test="not(driver:type[2])">
                <xsl:variable name="bug-type" select="driver:type"/>
                <xsl:variable name="resolution" select="driver:type/@resolution"/>
                <xsl:apply-templates select="document($doc-url)/rss">
                    <xsl:with-param name="doc-package-name" select="$doc-package-name"/>
                    <xsl:with-param name="components" select="key(packages, $doc-package-name)/driver:component"/>
                    <xsl:with-param name="bug-type" select="$bug-type"/>
                    <xsl:with-param name="resolution" select="$resolution"/>
                </xsl:apply-templates>
            </xsl:if>
            </section>
        </exsl:document>
    </xsl:template>
    <!-- frag generation templates -->

    <xsl:template match="rss">
        <xsl:param name="doc-package-name"/>
        <xsl:param name="components"/>
        <xsl:param name="bug-type"/>
        <xsl:param name="bug-type"/>
        <xsl:param name="resolution"/>

        <para>
            <xsl:if test="channel/item[type=$bug-type][resolution = $resolution or not($resolution)]">
                <itemizedlist>
                    <xsl:for-each select=".//item[./type = $bug-type]">
                        <xsl:sort select="substring-before(key, '-')"/>
                        <xsl:sort select="substring-after(key, '-')" data-type="number"/>

                        <xsl:apply-templates select=".">
                            <xsl:with-param name="doc-package-name" select="$doc-package-name"/>
                            <xsl:with-param name="components" select="$components"/>
                            <xsl:with-param name="bug-type" select="bug-type"/>
                            <xsl:with-param name="resolution" select="resolution"/>
                        </xsl:apply-templates>
                    </xsl:for-each>
                </itemizedlist>
            </xsl:if>
            <xsl:if test="not(channel/item[type=$bug-type][resolution = $resolution or not($resolution)])">
                <xsl:text>None.</xsl:text>
            </xsl:if>
        </para>
    </xsl:template>

    <xsl:template match="item">
        <xsl:param name="doc-package-name"/>
        <xsl:param name="components"/>
        <xsl:param name="bug-type"/>

        <xsl:variable name="bug-url" select="link"/>
        <xsl:variable name="bug-number" select="key"/>
        <xsl:variable name="bug-title" select="summary"/>

        <listitem>
            <simpara><ulink url="{$bug-url}"><xsl:value-of select="$bug-number"/></ulink>
            <xsl:text>: </xsl:text>
            <xsl:value-of select="$bug-title"/></simpara>
        </listitem>
    </xsl:template>

    <xsl:template name="replace">
        <xsl:param name="str"/>
        <xsl:param name="old"/>
        <xsl:param name="new"/>

        <xsl:if test="contains($str, $old)">
            <xsl:value-of select="substring-before($str, $old)"/>
            <xsl:if test="starts-with(substring-after($str, $old), $old)">
                <xsl:call-template name="replace">
                    <xsl:with-param name="str">
                        <xsl:value-of select="substring-after(substring-after($str, $old),$old)"/>
                    </xsl:with-param>
                    <xsl:with-param name="old">
                        <xsl:value-of select="$old"/>
                    </xsl:with-param>
                    <xsl:with-param name="new">
                        <xsl:value-of select="$new"/>
                    </xsl:with-param>
                </xsl:call-template>
            </xsl:if>
            <xsl:if test="not(starts-with(substring-after($str, $old), $old))">
                <xsl:value-of select="$new"/>
                <xsl:call-template name="replace">
                    <xsl:with-param name="str" select="substring-after($str, $old)"/>
                    <xsl:with-param name="old" select="$old"/>
                    <xsl:with-param name="new" select="$new"/>
                </xsl:call-template>
            </xsl:if>
        </xsl:if>
        <xsl:if test="not(contains($str, $old))">
            <xsl:value-of select="$str"/>
        </xsl:if>
    </xsl:template>

</xsl:stylesheet>
