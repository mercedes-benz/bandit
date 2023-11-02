<?xml version="1.0"?>

<!-- This XSLT transformation converts the output of sarif.py which is a basic XML structure:

    <testsuite>
        <testcase>
            [...]
        </testcase>
        [...]
        <metrics>[...]</metrics>
     </testsuite>

     into the Sarif JSON format. The XML structure is taken from the XML formatter plugin,
     but PCDATA text is put into XML attributes for easier processing.

     XSLT is used because the official MITRE Common Weakness Enumeration (CWE) is available as XML file
     (cwec_v4.12.xml) in one go into the XSLT stylesheet. The lookup of CWE elements can be
     performed very easily using XPATH selection, e.g.

     <xsl:variable name="cwe-finding" select="$cwe-data//cwe:Weakness[@ID=$cwe-id]"/>

     In order to have a convenient process, there are two processing steps:

     1. Processing step: The input XML structure is converted to a Sarif like XML structure.
        The attribute
            - @json = { 'property' | 'anonymous-object' | 'named-object' | 'named-list' }
        denotes if the XML element will be converted to a JSON property, list or object in the second step.

     2. Processing step: The XML structure will be converted to JSON. It will be appended to the root output tree
        as one single text node. (It appears that the lxml XSLT library does not support for <xsl:output method="text"/>)

-->

<xsl:stylesheet version="1.0"
                xmlns:bandit-sarif="local://bandit-sarif"
                xmlns:cwe="http://cwe.mitre.org/cwe-7"
                xmlns:exsl="http://exslt.org/common"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

    <xsl:variable name="cwe-data" select="document(concat('file://',bandit-sarif:cwe-data-xml()))"/>
    <xsl:variable name="taxonomy-guid" select="/testsuite/@cwe_guid"/>

    <!-- start template -->

    <xsl:template match="/">
        <root>
            <!-- first processing step -->
            <xsl:variable name="pre">
                <xsl:copy>
                    <xsl:apply-templates/>
                </xsl:copy>
            </xsl:variable>
            <!-- second processing step -->
            <xsl:apply-templates select="exsl:node-set($pre)" mode="post"/>
        </root>
    </xsl:template>

    <!-- first processing step: convert XML structure to Sarif like XML structure -->

    <xsl:template name="tool">
        <tool json="named-object">
            <driver json="named-object">
                <name json="property">
                    <xsl:value-of select="@name"/>
                </name>
                <rules json="named-list">
                    <xsl:apply-templates select="testcase[not(@id=preceding-sibling::*/@id)]">
                        <xsl:with-param name="type">tool</xsl:with-param>
                    </xsl:apply-templates>
                </rules>
                <version json="property">
                    <xsl:value-of select="bandit-sarif:get-bandit-version()"/>
                </version>
                <informationUri json="property">
                    <xsl:value-of select="bandit-sarif:get-bandit-information-uri()"/>
                </informationUri>
                <supportedTaxonomies json="named-list">
                    <supportedTaxonomy json="anonymous-object">
                        <name json="property">
                            <xsl:value-of select="$cwe-data/cwe:Weakness_Catalog/@Name"/>
                        </name>
                        <guid json="property">
                            <xsl:value-of select="$taxonomy-guid"/>
                        </guid>
                    </supportedTaxonomy>
                </supportedTaxonomies>
            </driver>
        </tool>
    </xsl:template>

    <xsl:template name="results">
        <results json="named-list">
            <xsl:apply-templates select="testcase">
                <xsl:with-param name="type">results</xsl:with-param>
            </xsl:apply-templates>
        </results>
    </xsl:template>

    <xsl:template name="invocations">
        <invocations json="named-list">
            <invocation json="anonymous-object">
                <executionSuccessful json="property" type="boolean">true</executionSuccessful>
                <endTimeUtc json="property">
                    <xsl:value-of select="bandit-sarif:endtime-utc()"/>
                </endTimeUtc>
            </invocation>
        </invocations>
    </xsl:template>

    <xsl:template name="properties">
        <properties json="named-object">
            <xsl:value-of disable-output-escaping="yes" select="concat('&quot;metrics&quot;:',//metrics)"/>
        </properties>
    </xsl:template>

    <xsl:template name="taxonomies">
        <taxonomies json="named-list">
            <taxonomy json="anonymous-object">
                <name json="property">
                    <xsl:value-of select="$cwe-data/cwe:Weakness_Catalog/@Name"/>
                </name>
                <version json="property">
                    <xsl:value-of select="$cwe-data/cwe:Weakness_Catalog/@Version"/>
                </version>
                <releaseDateUtc json="property">
                    <xsl:value-of select="$cwe-data/cwe:Weakness_Catalog/@Date"/>
                </releaseDateUtc>
                <guid json="property">
                    <xsl:value-of select="$taxonomy-guid"/>
                </guid>
                <informationUri json="property">
                    <xsl:value-of select="bandit-sarif:get-information-uri()"/>
                </informationUri>
                <downloadUri json="property">
                    <xsl:value-of select="bandit-sarif:get-download-uri()"/>
                </downloadUri>
                <organization json="property">
                    <xsl:value-of select="bandit-sarif:get-organization-name()"/>
                </organization>
                <shortDescription json="named-object">
                    <text json="property">
                        <xsl:value-of select="bandit-sarif:get-organization-description()"/>
                    </text>
                </shortDescription>
                <taxa json="named-list">
                    <xsl:apply-templates select="testcase[not(@cwe=preceding-sibling::*/@cwe)]">
                        <xsl:with-param name="type">taxonomies</xsl:with-param>
                    </xsl:apply-templates>
                </taxa>
            </taxonomy>
        </taxonomies>
    </xsl:template>

    <xsl:template match="testsuite">
        <sarif-report json="anonymous-object">
            <runs json="named-list">
                <run json="anonymous-object">
                    <xsl:call-template name="tool"/>
                    <xsl:call-template name="invocations"/>
                    <xsl:call-template name="properties"/>
                    <xsl:call-template name="results"/>
                    <xsl:call-template name="taxonomies"/>
                </run>
            </runs>
            <version json="property">
                <xsl:value-of select="bandit-sarif:get-sarif-schema-version()"/>
            </version>
            <schema>
                <xsl:value-of select="bandit-sarif:get-sarif-schema-location()"/>
            </schema>
        </sarif-report>
    </xsl:template>

    <xsl:template name="determine-level">
        <xsl:param name="severity"/>
        <xsl:choose>
            <xsl:when test="$severity='High'">error</xsl:when>
            <xsl:when test="$severity='Medium'">warning</xsl:when>
            <xsl:when test="$severity='Low'">note</xsl:when>
            <xsl:otherwise>none</xsl:otherwise>
        </xsl:choose>
    </xsl:template>

    <xsl:template name="result-in-tool">
        <xsl:param name="taxa-guid"/>
        <xsl:variable name="cwe-id" select="@cwe"/>
        <xsl:variable name="cwe-finding" select="$cwe-data//cwe:Weakness[@ID=$cwe-id]"/>
        <result json="anonymous-object">
            <id json="property">
                <xsl:value-of select="@id"/>
            </id>
            <name json="property">
                <xsl:value-of select="@name"/>
            </name>
            <relationships json="named-list">
                <relationship json="anonymous-object">
                    <target json="named-object">
                        <id json="property">
                            <xsl:value-of select="$cwe-finding/@ID"/>
                        </id>
                        <guid json="property">
                            <xsl:value-of select="$taxonomy-guid"/>
                        </guid>
                        <toolComponent json="named-object">
                            <name json="property">CWE</name>
                            <guid json="property">
                                <xsl:value-of select="$taxa-guid"/>
                            </guid>
                        </toolComponent>
                    </target>
                    <kinds/>
                </relationship>
            </relationships>
            <helpUri json="property">
                <xsl:value-of select="error/@more_info"/>
            </helpUri>
        </result>
    </xsl:template>

    <xsl:template name="taxa-in-taxonomies">
        <xsl:variable name="cwe-id" select="@cwe"/>
        <xsl:variable name="cwe-finding" select="$cwe-data//cwe:Weakness[@ID=$cwe-id]"/>
        <xsl:variable name="severity" select="$cwe-finding//cwe:Likelihood_Of_Exploit"/>
        <taxa-element json="anonymous-object">
            <id json="property">
                <xsl:value-of select="$cwe-id"/>
            </id>
            <guid json="property">
                <xsl:value-of select="@taxa_guid"/>
            </guid>
            <name json="property">
                <xsl:value-of select="$cwe-finding/@Name"/>
            </name>
            <shortDescription json="named-object">
                <text json="property">
                    <xsl:value-of select="bandit-sarif:format-description($cwe-finding//cwe:Description)"/>
                </text>
            </shortDescription>
            <defaultConfiguration json="named-object">
                <level json="property">
                    <xsl:call-template name="determine-level">
                        <xsl:with-param name="severity" select="$severity"/>
                    </xsl:call-template>
                </level>
            </defaultConfiguration>
        </taxa-element>
    </xsl:template>

    <xsl:template name="result-in-results">
        <xsl:param name="taxa-guid"/>
        <xsl:variable name="cwe-id" select="@cwe"/>
        <xsl:variable name="cwe-finding" select="$cwe-data//cwe:Weakness[@ID=$cwe-id]"/>
        <xsl:variable name="severity" select="$cwe-finding//cwe:Likelihood_Of_Exploit"/>
        <result json="anonymous-object">
            <message json="named-object">
                <text json="property">
                    <xsl:value-of select="error/@message"/>
                </text>
            </message>
            <level json="property">
                <xsl:call-template name="determine-level">
                    <xsl:with-param name="severity" select="$severity"/>
                </xsl:call-template>
            </level>
            <locations json="named-list">
                <location json="anonymous-object">
                    <physicalLocation json="named-object">
                        <region json="named-object">
                            <snippet json="named-object">
                                <text json="property">
                                    <xsl:value-of select="bandit-sarif:get-vulnerable-code-line(@code)"/>
                                </text>
                            </snippet>
                            <startLine json="property" type="integer">
                                <xsl:value-of select="@location"/>
                            </startLine>
                        </region>
                        <artifactLocation json="named-object">
                            <uri json="property">
                                <xsl:value-of select="@filename"/>
                            </uri>
                        </artifactLocation>
                        <contextRegion json="named-object">
                            <xsl:variable name="all-lines" select="bandit-sarif:get-all-code-lines(@code)"/>
                            <snippet json="named-object">
                                <text json="property">
                                    <xsl:value-of select="$all-lines"/>
                                </text>
                            </snippet>
                            <endLine json="property" type="integer">
                                <xsl:value-of select="@location + bandit-sarif:count-lines($all-lines)"/>
                            </endLine>
                            <startLine json="property" type="integer">
                                <xsl:value-of select="@location - 1"/>
                            </startLine>
                        </contextRegion>
                    </physicalLocation>
                </location>
            </locations>
            <properties json="named-object">
                <issue_confidence json="property">
                    <xsl:value-of select="@confidence"/>
                </issue_confidence>
                <issue_severity json="property">
                    <xsl:value-of select="@severity"/>
                </issue_severity>
            </properties>
            <taxa json="named-list">
                <xsl:call-template name="taxa-in-result">
                    <xsl:with-param name="type">taxa-in-result</xsl:with-param>
                    <xsl:with-param name="taxa-guid" select="$taxa-guid"/>
                </xsl:call-template>
            </taxa>
            <ruleId json="property">
                <xsl:value-of select="@id"/>
            </ruleId>
            <ruleIndex json="property" type="integer">
                <xsl:value-of select="bandit-sarif:get-rule-index(@id)"/>
            </ruleIndex>
        </result>
    </xsl:template>

    <xsl:template name="taxa-in-result">
        <xsl:param name="taxa-guid"/>
        <xsl:variable name="cwe-id" select="@cwe"/>
        <taxa-element json="anonymous-object">
            <id json="property">
                <xsl:value-of select="$cwe-id"/>
            </id>
            <guid json="property">
                <xsl:value-of select="$taxonomy-guid"/>
            </guid>
            <toolComponent json="named-object">
                <name json="property">CWE</name>
                <guid json="property"><xsl:value-of select="$taxa-guid"/></guid>
            </toolComponent>
        </taxa-element>
    </xsl:template>

    <xsl:template match="testcase">
        <xsl:param name="type"/>
        <xsl:variable name="taxa-guid" select="@taxa_guid"/>
        <xsl:choose>
            <xsl:when test="$type='tool'">
                <xsl:call-template name="result-in-tool">
                    <xsl:with-param name="taxa-guid" select="$taxa-guid"/>
                </xsl:call-template>
            </xsl:when>
            <xsl:when test="$type='taxonomies'">
                <xsl:call-template name="taxa-in-taxonomies"/>
            </xsl:when>
            <xsl:when test="$type='results'">
                 <xsl:call-template name="result-in-results">
                     <xsl:with-param name="taxa-guid" select="$taxa-guid"/>
                </xsl:call-template>
            </xsl:when>
        </xsl:choose>
    </xsl:template>

    <!-- second processing step: convert Sarif like XML structure to JSON -->

    <!-- if you update the JSON elements above due to schema changes you  -->
    <!-- typically would not need to touch the lines below since these    -->
    <!-- rules implement a rather generic XML to JSON mapping.            -->

    <xsl:template match="*[@json='anonymous-object']" mode="post">
        <xsl:text>{</xsl:text>
        <xsl:apply-templates select="node()|@*" mode="post"/>
        <xsl:text>}</xsl:text>
       <xsl:if test="following-sibling::*">,</xsl:if>
    </xsl:template>

    <xsl:template match="*[@json='named-list']" mode="post">
        <xsl:text>"</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:text>"</xsl:text>
        <xsl:text>:[</xsl:text>
        <xsl:apply-templates select="node()|@*" mode="post"/>
        <xsl:text>]</xsl:text>
       <xsl:if test="following-sibling::*">,</xsl:if>
    </xsl:template>

    <xsl:template match="*[@json='named-object']" mode="post">
        <xsl:text>"</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:text>"</xsl:text>
        <xsl:text>:{</xsl:text>
        <xsl:apply-templates select="node()|@*" mode="post"/>
        <xsl:text>}</xsl:text>
        <xsl:if test="following-sibling::*">,</xsl:if>
    </xsl:template>

    <xsl:template match="@json" mode="post"/>

    <xsl:template match="*[@json='property']" mode="post">
        <xsl:text>"</xsl:text>
        <xsl:value-of select="name()"/>
        <xsl:choose>
            <xsl:when test="@type='boolean' or @type='integer'">
                <xsl:text>":</xsl:text>
                <xsl:value-of select="."/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:text>":"</xsl:text>
                <xsl:value-of select="."/>
                <xsl:text>"</xsl:text>
            </xsl:otherwise>
        </xsl:choose>
        <xsl:if test="following-sibling::*">,</xsl:if>
    </xsl:template>

    <!-- some special elements which cannot be otherwise mapped -->

    <xsl:template match="kinds" mode="post">
        <xsl:text>"kinds": ["superset"]</xsl:text>
    </xsl:template>

    <xsl:template match="schema" mode="post">
        <xsl:text>"$schema":"</xsl:text>
        <xsl:value-of select="."/>
        <xsl:text>"</xsl:text>
    </xsl:template>

</xsl:stylesheet>