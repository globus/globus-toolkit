<?xml version="1.0"?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    xmlns:driver="http://www.globus.org/generate-frags-driver"
    exclude-result-prefixes="exsl driver"
    extension-element-prefixes="exsl"
    version="1.0"
    >

    <xsl:param name="release-version" select="'5.2.1'"/>

    <xsl:key name="packages" match="driver:package" use="@name"/>
    <xsl:key name="frags" match="driver:frag" use="@name"/>

    <xsl:template match="text()"/>
    <xsl:template match="/driver:docs">
        <xsl:apply-templates select="driver:packages"/>
    </xsl:template>

    <!-- driver template which reads the list of frags to generate from which
         components
      -->
    <xsl:template match="driver:package">
        <xsl:message>Processing package <xsl:value-of select="@name"/>&#10;</xsl:message>
        <xsl:variable name='url-start' select="'http://jira.globus.org/sr/jira.issueviews:searchrequest-xml/temp/SearchRequest.xml?jqlQuery='"/>
        <xsl:variable name='url-end' select="'+ORDER+BY+Ranking+ASC%2C+key+ASC&amp;tempMax=1000'"/>
        <xsl:variable name="project-query">
            <xsl:apply-templates select='driver:project' mode='generate-query'/>
        </xsl:variable>

        <xsl:variable name="label-query">
            <xsl:apply-templates select='driver:label' mode='generate-query'/>
        </xsl:variable>

        <xsl:variable name="version-query" select="concat('fixVersion+%3D+%22', $release-version, '%22')"/>

        <xsl:variable name="url-with-spaces">
            <xsl:choose>
                <xsl:when test="$project-query != '' and $label-query != ''">
                    <xsl:value-of select="concat($url-start,
                                                    $version-query, '+AND+',
                                                    '(', $project-query, '+OR+',
                                                    $label-query, ')',
                                                    $url-end)"/>
                </xsl:when>
                <xsl:when test="$project-query != '' and $label-query = ''">
                    <xsl:value-of select="concat($url-start,
                                                    $version-query, '+AND+',
                                                    $project-query,
                                                    $url-end)"/>
                </xsl:when>
                <xsl:when test="$project-query = '' and $label-query != ''">
                    <xsl:value-of select="concat($url-start,
                                                    $version-query, '+AND+',
                                                    $label-query, 
                                                    $url-end)"/>
                </xsl:when>
                <xsl:otherwise>
                    <xsl:value-of select="concat($url-start,
                                                    $version-query,
                                                    $url-end)"/>
                </xsl:otherwise>
            </xsl:choose>
        </xsl:variable>

        <xsl:variable name="url">
            <xsl:call-template name="replace">
                <xsl:with-param name="str">
                    <xsl:call-template name="replace">
                        <xsl:with-param name="str" select="$url-with-spaces"/>
                        <xsl:with-param name="old" select="'&#10;'"/>
                        <xsl:with-param name="new" select="'+'"/>
                    </xsl:call-template>
                </xsl:with-param>
                <xsl:with-param name="old" select="' '"/>
                <xsl:with-param name="new" select="'+'"/>
            </xsl:call-template>
        </xsl:variable>

        <xsl:variable name="open-bugs-url-with-spaces">
            <xsl:choose>
                <xsl:when test="$project-query != '' and $label-query != ''">
                    <xsl:value-of select="
                        concat(
                            $url-start,
                            '(',
                            $project-query, ' OR ',
                            $label-query, ') AND ',
                            '(',
                            '    affectedVersion %3D %22', $release-version, '%22',
                            ' AND ',
                            ' ( ',
                            '     NOT ',
                            '     ( ',
                            '        fixVersion %3D %22', $release-version, '%22',
                            '     ) ',
                            '     OR ',
                            '     (resolution %3D Unresolved)',
                            ' )',
                            ')',
                            $url-end)"/>
                </xsl:when>
                <xsl:when test="$project-query != '' and $label-query = ''">
                    <xsl:value-of select="
                        concat(
                            $url-start,
                            $project-query, ' AND ',
                            '(',
                            '    affectedVersion %3D %22', $release-version, '%22',
                            ' AND ',
                            ' ( ',
                            '     NOT ',
                            '     ( ',
                            '        fixVersion %3D %22', $release-version, '%22',
                            '     ) ',
                            '     OR ',
                            '     (resolution %3D Unresolved)',
                            ' )',
                            ')',
                            $url-end)"/>
                </xsl:when>
                <xsl:when test="$project-query = '' and $label-query != ''">
                    <xsl:value-of select="
                        concat(
                            $url-start,
                            $label-query, ' AND ',
                            '(',
                            '    affectedVersion %3D %22', $release-version, '%22',
                            ' AND ',
                            ' ( ',
                            '     NOT ',
                            '     ( ',
                            '        fixVersion %3D %22', $release-version, '%22',
                            '     ) ',
                            '     OR ',
                            '     (resolution %3D Unresolved)',
                            ' )',
                            ')',
                            $url-end)"/>
                </xsl:when>
                <xsl:when test="$project-query = '' and $label-query = ''">
                    <xsl:value-of select="
                        concat(
                            $url-start,
                            '(',
                            '    affectedVersion %3D %22', $release-version, '%22',
                            ' AND ',
                            ' ( ',
                            '     NOT ',
                            '     ( ',
                            '        fixVersion %3D %22', $release-version, '%22',
                            '     ) ',
                            '     OR ',
                            '     (resolution %3D Unresolved)',
                            ' )',
                            ')',
                            $url-end)"/>
                </xsl:when>
            </xsl:choose>
        </xsl:variable>

        <xsl:variable name="open-bugs-url">
            <xsl:call-template name="replace">
                <xsl:with-param name="str">
                    <xsl:call-template name="replace">
                        <xsl:with-param name="str" select="$open-bugs-url-with-spaces"/>
                        <xsl:with-param name="old" select="'&#10;'"/>
                        <xsl:with-param name="new" select="'+'"/>
                    </xsl:call-template>
                </xsl:with-param>
                <xsl:with-param name="old" select="' '"/>
                <xsl:with-param name="new" select="'+'"/>
            </xsl:call-template>
        </xsl:variable>

        <!--
        <xsl:message>open bugs url is <xsl:value-of select="$open-bugs-url"/></xsl:message>
        <xsl:message>closed bugs url is <xsl:value-of select="$url"/></xsl:message>
        -->


        <xsl:apply-templates select="//driver:frags/driver:frag[not(@open = 'true')]" mode="output">
            <xsl:with-param name="doc-url" select="$url"/>
            <xsl:with-param name="doc-package-name" select="@name"/>
            <xsl:with-param name="doc-package-prefix" select="@prefix"/>
        </xsl:apply-templates>

        <xsl:apply-templates select="//driver:frags/driver:frag[@open = 'true']" mode="output">
            <xsl:with-param name="doc-url" select="$open-bugs-url"/>
            <xsl:with-param name="doc-package-name" select="@name"/>
            <xsl:with-param name="doc-package-prefix" select="@prefix"/>
        </xsl:apply-templates>
    </xsl:template>

    <xsl:template match='driver:project[1]' mode='generate-query'>
        <xsl:text>+(+</xsl:text>
        <xsl:value-of select="concat('project+%3D+%22', @name, '%22')"/>
        <xsl:if test="driver:component">
            <xsl:text>+AND+(+</xsl:text>
            <xsl:apply-templates mode='generate-query'/>
            <xsl:text>+)+</xsl:text>
        </xsl:if>
        <xsl:text>+)+</xsl:text>
    </xsl:template>

    <xsl:template match='driver:project' mode='generate-query'>
        <xsl:text>+OR+(+</xsl:text>
        <xsl:value-of select="concat('project+%3D+%22', @name, '%22')"/>
        <xsl:if test="driver:component">
            <xsl:text>+AND+(+</xsl:text>
            <xsl:apply-templates mode='generate-query'/>
            <xsl:text>+)+</xsl:text>
        </xsl:if>
        <xsl:text>+)+</xsl:text>
    </xsl:template>

    <xsl:template match='driver:component' mode='generate-query'>
        <xsl:if test="preceding-sibling::*[name(.) = name(current())]">
            <xsl:text>+OR+</xsl:text>
        </xsl:if>
        <xsl:value-of select="concat(local-name(.), '+%3D+%22', text(), '%22')"/>
    </xsl:template>

    <xsl:template match='driver:label' mode='generate-query'>
        <xsl:if test="preceding-sibling::*[name(.) = name(current())]">
            <xsl:text>+OR+</xsl:text>
        </xsl:if>
        <xsl:value-of select="concat('labels+%3D+%22', text(), '%22')"/>
    </xsl:template>

</xsl:stylesheet>
