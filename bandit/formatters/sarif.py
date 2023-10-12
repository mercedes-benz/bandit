#
# SPDX-License-Identifier: Apache-2.0
r"""
=============
Sarif Formatter
=============

This formatter outputs the issues as Sarif.

"""
import logging
import sys, os, uuid, datetime, json

from lxml import etree


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
    global rules
    issues = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)
    root = etree.Element("testsuite", name="Bandit", tests=str(len(issues)))
    for issue in issues:
        id = str(issue.test_id)
        code = issue.as_dict()['code']
        if not id in rules:
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
            code=code
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

    metrics = str(manager.metrics.data).replace("'",'"')
    etree.SubElement(
        root,
        "metrics"
        ).text = metrics

    tree = etree.ElementTree(root)

    if fileobj.name == sys.stdout.name:
        fileobj = sys.stdout.buffer
    elif fileobj.mode == "w":
        fileobj.close()
        fileobj = open(fileobj.name, "w", encoding="utf-8")

    with fileobj:
        # We register namespace functions that can be called inside the XSLT transformation
        register_stylesheet_functions()
        # Read the XSLT stylesheet
        xsl = etree.XML(open(SARIF_TRANSFORMATION_FILE, "r", encoding="utf-8").read())
        # Transform the XML to Sarif JSON and put it into the root text node
        transform = etree.XSLT(xsl)
        result = transform(tree)
        if INDENT:
            # Load into python dict and pretty print when writing back to JSON
            jsn = json.loads(result.getroot().text)
            fileobj.write(json.dumps(jsn, indent=2))
        else:
            fileobj.write(result.getroot().text)

    if fileobj.name != sys.stdout.name:
        LOG.info("XML output written to file: %s", fileobj.name)


def register_stylesheet_functions():
    """Make these functions available in the XSLT stylesheet."""
    namespace = etree.FunctionNamespace("local://bandit-sarif")
    namespace["cwe-data-xml"] = get_cwe_data_xml
    namespace["uuid"] = get_uuid
    namespace["endtime-utc"] = endtime_utc
    namespace["get-vulnerable-code-line"] = get_vulnerable_code_line
    namespace["get-all-code-lines"] = get_all_code_lines
    namespace["format-description"] = format_description
    namespace["count-lines"] = count_lines
    namespace["get-rule-index"] = get_rule_index


def get_cwe_data_xml(context):
    """Called by the XSLT stylesheet and returns the path to the CWE XML file."""
    return CWE_DATA_XML


def get_uuid(context):
    """Called by the XSLT stylesheet and returns a unique ID."""
    return str(uuid.uuid4())


def endtime_utc(context):
    """Called by the XSLT stylesheet and returns end time utc."""
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def get_vulnerable_code_line(context, code):
    """Called by the XSLT stylesheet and return the vulnerable line of the code block."""
    # code block does always consist of three lines: the vulnerable line is in the middle
    vulnerable_line = code[0].split('\n')[1]
    # remove line number
    vulnerable_line_content = vulnerable_line.split(' ',1)[1]
    # remove leading and trailing quotes, escape for json and return
    return json.dumps(vulnerable_line_content)[1:-1]+'\\n'


def get_all_code_lines(context, code):
    """Called by the XSLT stylesheet and return all the lines of the code block."""
    # remove line numbers, remove leading and trailing quotes and return
    codelines = [line.split(' ',1)[1] for line in code[0].split('\n') if len(line) > 1]
    return "\\n".join([json.dumps(line)[1:-1] for line in codelines])+'\\n'


def format_description(context, description):
    """Called by the XSLT stylesheet and fixes the cwe:Description text block."""
    return description[0].text.replace('\n','\\n')


def count_lines(context, code):
    """Called by the XSLT stylesheet and count lines of code block."""
    return len(code.split('\n'))


def get_rule_index(context, rule_id):
    """Called by the XSLT stylesheet and get the index of the rule in the rules array."""
    return rules.index(rule_id[0])
