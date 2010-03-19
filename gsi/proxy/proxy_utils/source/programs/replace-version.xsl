<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version="1.0">
    <xsl:import href="http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl"/>
    <xsl:param name="version"/>

    <xsl:template match="/">
      <xsl:apply-imports/>
    </xsl:template>

    <xsl:template match="replaceable[@role='entity']">
        <xsl:if test="text() = 'version'">
            <xsl:value-of select="$version"/>
        </xsl:if>
    </xsl:template>

</xsl:stylesheet>
