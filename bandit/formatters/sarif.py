#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=c-extension-no-member

r"""
=============
Sarif Formatter
=============

This formatter outputs the security report in the
Static Analysis Results Interchange Format (SARIF) .

"""
import datetime
import json
import logging
import os
import sys
import uuid

from lxml import etree

import bandit
from bandit.core import docs_utils

LOG = logging.getLogger(__name__)

INDENT = True
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
CWE_DATA_XML = os.path.join(SCRIPT_PATH, "sarif", "cwec_v4.12.xml")
SARIF_TRANSFORMATION_FILE = os.path.join(SCRIPT_PATH, "sarif", "sarif.xsl")

rules = []


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Prints issues in Sarif format using the XSLT stylesheet in sarif/sarif.xsl

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """
    issues = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)
    root = etree.Element(
        "testsuite", name="Bandit", tests=str(len(issues)), cwe_guid=str(uuid.uuid4())
    )
    for issue in issues:
        id = str(issue.test_id)
        code = issue.as_dict()["code"]
        if id not in rules:
            rules.append(id)
        testcase = etree.SubElement(
            root,
            "testcase",
            classname=str(issue.fname),
            name=str(issue.test),
            id=id,
            severity=str(issue.severity),
            confidence=str(issue.confidence),
            cwe=str(issue.cwe.id),
            cwe_link=str(issue.cwe.link),
            filename=str(issue.fname),
            location=str(issue.lineno),
            code=code,
            taxa_guid=str(uuid.uuid4()),
        )

        etree.SubElement(
            testcase,
            "error",
            more_info=docs_utils.get_url(issue.test_id),
            type=issue.severity,
            message=issue.text,
        )

    # Bandit outputs the metrics data as JSON with single quotes,
    # so we just attach this data to the root element
    # and replace the single quotes with double quotes.

    metrics = str(manager.metrics.data).replace("'", '"')
    etree.SubElement(root, "metrics").text = metrics

    tree = etree.ElementTree(root)

    if fileobj.name == sys.stdout.name:
        fileobj = sys.stdout.buffer
    elif fileobj.mode == "w":
        fileobj.close()
        fileobj = open(fileobj.name, "w", encoding="utf-8")

    with fileobj:
        # Register namespace functions that can be called inside the XSLT transformation
        register_stylesheet_functions()
        # Read the XSLT stylesheet
        xsl = etree.XML(open(SARIF_TRANSFORMATION_FILE, "r", encoding="utf-8").read())
        # Transform the XML to Sarif JSON and put it into the root text node
        transform = etree.XSLT(xsl)
        result = transform(tree)
        if INDENT:
            # Load into python dict and pretty print when writing back to JSON
            json_text = json.loads(result.getroot().text)
            fileobj.write(json.dumps(json_text, indent=2))
        else:
            fileobj.write(result.getroot().text)

    if fileobj.name != sys.stdout.name:
        LOG.info("XML output written to file: %s", fileobj.name)


def register_stylesheet_functions():
    """Make these functions available in the XSLT stylesheet."""
    namespace = etree.FunctionNamespace("local://bandit-sarif")
    namespace["cwe-data-xml"] = get_cwe_data_xml
    namespace["endtime-utc"] = endtime_utc
    namespace["get-vulnerable-code-line"] = get_vulnerable_code_line
    namespace["get-all-code-lines"] = get_all_code_lines
    namespace["format-description"] = format_description
    namespace["count-lines"] = count_lines
    namespace["get-rule-index"] = get_rule_index
    namespace["get-bandit-version"] = get_bandit_version
    namespace["get-information-uri"] = get_information_uri
    namespace["get-download-uri"] = get_download_uri
    namespace["get-organization-name"] = get_organization_name
    namespace["get-organization-description"] = get_organization_description
    namespace["get-sarif-schema-version"] = get_sarif_schema_version
    namespace["get-sarif-schema-location"] = get_sarif_schema_location
    namespace["get-bandit-information-uri"] = get_bandit_information_uri


def get_cwe_data_xml(context):
    """Called by the XSLT stylesheet and returns the path to the CWE XML file."""
    return CWE_DATA_XML


def get_information_uri(context):
    """Called by the XSLT stylesheet and returns information uri of the CWE catalog."""
    return "https://cwe.mitre.org/data/published/cwe_v4.12.pdf"


def get_download_uri(context):
    """Called by the XSLT stylesheet and returns the download uri of the CWE catalog."""
    return "https://cwe.mitre.org/data/xml/cwec_v4.12.xml.zip"


def get_organization_name(context):
    """Called by the XSLT stylesheet and returns the MITRE organization name."""
    return "MITRE"


def get_organization_description(context):
    """Called by the XSLT stylesheet and returns the organization short description."""
    return "The MITRE Common Weakness Enumeration"


def get_sarif_schema_version(context):
    """Called by the XSLT stylesheet and returns the Sarif JSON schema version."""
    return "2.1.0"


def get_sarif_schema_location(context):
    """Called by the XSLT stylesheet and returns the Sarif JSON schema location."""
    return "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"


def get_bandit_information_uri(context):
    """Called by the XSLT stylesheet and returns the Bandit GitHub uri."""
    return "https://github.com/PyCQA/bandit/tree/main"


def endtime_utc(context):
    """Called by the XSLT stylesheet and returns end time in UTC format."""
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def get_vulnerable_code_line(context, code):
    """Called by the XSLT stylesheet and return the vulnerable line of the code block."""
    # normally code block consist of minimum three lines: the vulnerable line is second
    # but e.g. in a test case the code block may be mocked shorter or empty
    lines = code[0].split("\n")
    if len(lines) > 1:
        vulnerable_line = lines[1]
    else:
        vulnerable_line = lines[0]
    # remove line number if exists. line number is separated by whitespace
    line_split = vulnerable_line.split(" ", 1)
    if len(line_split) > 1:
        vulnerable_line_content = line_split[1]
    else:
        vulnerable_line_content = line_split[0]
    # remove leading and trailing quotes, escape for json and return
    return json.dumps(vulnerable_line_content)[1:-1]


def get_all_code_lines(context, code):
    """Called by the XSLT stylesheet and return all the lines of the code block."""
    # remove line numbers, remove leading and trailing quotes and return
    codelines = [line.split(" ", 1)[1] for line in code[0].split("\n") if len(line) > 1]
    return "\\n".join([json.dumps(line)[1:-1] for line in codelines])


def format_description(context, description):
    """Called by the XSLT stylesheet and fixes the cwe:Description text block."""
    return description[0].text.replace("\n", "\\n")


def count_lines(context, code):
    """Called by the XSLT stylesheet and count lines of code block."""
    return len(code.split("\n"))


def get_rule_index(context, rule_id):
    """Called by the XSLT stylesheet and get the index of the rule in the rules array."""
    return rules.index(rule_id[0])


def get_bandit_version(context):
    """Called by the XSLT stylesheet and get the version number of Bandit."""
    return bandit.__version__
