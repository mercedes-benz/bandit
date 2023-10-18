import json
import tempfile
from unittest import mock

import testtools

import bandit
from bandit.core import config, constants, docs_utils, issue, manager, metrics
from bandit.formatters import sarif as bandit_sarif


class SarifFormatterTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, "file")
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.context = {"filename": self.tmp_fname, "lineno": 4}
        self.check_name = "hardcoded_bind_all_interfaces"
        self.issue = issue.Issue(
            bandit.MEDIUM,
            issue.Cwe.MULTIPLE_BINDS,
            bandit.MEDIUM,
            "Possible binding to all interfaces.",
        )

        self.manager.out_file = self.tmp_fname

        self.issue.fname = self.context["filename"]
        self.issue.lineno = self.context["lineno"]
        self.issue.test = self.check_name
        self.issue.test_id = "B104"

        self.manager.results.append(self.issue)
        self.manager.metrics = metrics.Metrics()

        # mock up the metrics
        for key in ["_totals", "binding.py"]:
            self.manager.metrics.data[key] = {"loc": 4, "nosec": 2}
            for criteria, default in constants.CRITERIA:
                for rank in constants.RANKING:
                    self.manager.metrics.data[key][f"{criteria}.{rank}"] = 0

    @mock.patch("bandit.core.manager.BanditManager.get_issue_list")
    def test_report(self, get_issue_list):
        self.manager.files_list = ["binding.py"]
        self.manager.scores = [
            {
                "SEVERITY": [0] * len(constants.RANKING),
                "CONFIDENCE": [0] * len(constants.RANKING),
            }
        ]

        get_issue_list.return_value = [self.issue]

        with open(self.tmp_fname, "w") as tmp_file:
            bandit_sarif.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            data = json.loads(f.read())

            # check properties field
            properties = data["runs"][0]["results"][0]["properties"]
            self.assertEqual(self.issue.severity, properties["issue_severity"])
            self.assertIsNotNone(data["runs"][0]["properties"]["metrics"]["binding.py"])
            self.assertEqual(self.issue.confidence, properties["issue_confidence"])

            # check taxonomies field
            taxonomies = data["runs"][0]["taxonomies"][0]
            self.assertIn(
                "Multiple Binds to the Same Port", taxonomies["taxa"][0]["name"]
            )
            self.assertIn(
                "other services on that port may be stolen or spoofed",
                taxonomies["taxa"][0]["shortDescription"]["text"],
            )
            self.assertEqual(
                bandit_sarif.get_organization_name(None), taxonomies["organization"]
            )
            self.assertEqual(
                bandit_sarif.get_organization_description(None),
                taxonomies["shortDescription"]["text"],
            )
            self.assertEqual(
                bandit_sarif.get_information_uri(None), taxonomies["informationUri"]
            )
            self.assertEqual(
                bandit_sarif.get_download_uri(None), taxonomies["downloadUri"]
            )
            self.assertEqual(
                "none", taxonomies["taxa"][0]["defaultConfiguration"]["level"]
            )

            # check rules field
            rules = data["runs"][0]["tool"]["driver"]["rules"][0]
            self.assertEqual(self.check_name, rules["name"])
            self.assertEqual(
                "CWE", rules["relationships"][0]["target"]["toolComponent"]["name"]
            )
            self.assertEqual(docs_utils.get_url(self.issue.test_id), rules["helpUri"])

            # check results field
            results = data["runs"][0]["results"][0]
            self.assertEqual(self.issue.text, results["message"]["text"])
            self.assertEqual(
                self.context["lineno"],
                results["locations"][0]["physicalLocation"]["region"]["startLine"],
            )
            self.assertEqual(
                self.tmp_fname,
                results["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            )

            # check driver field
            driver = data["runs"][0]["tool"]["driver"]
            self.assertEqual(
                bandit_sarif.get_bandit_information_uri(None), driver["informationUri"]
            )
            self.assertEqual("CWE", driver["supportedTaxonomies"][0]["name"])

            # check misc fields
            self.assertEqual(
                bandit_sarif.get_sarif_schema_version(None), data["version"]
            )
            self.assertEqual(
                bandit_sarif.get_sarif_schema_location(None), data["$schema"]
            )

            # check ids
            id_in_results_taxa = results["taxa"][0]["id"]
            id_in_taxonomies_taxa = taxonomies["taxa"][0]["id"]
            id_in_relationships = rules["relationships"][0]["target"]["id"]
            id_in_rules = rules["id"]
            self.assertEqual(self.issue.test_id, id_in_rules)
            self.assertTrue(
                id_in_results_taxa == id_in_taxonomies_taxa == id_in_relationships
            )

            # check guids
            guid_in_results_taxa = results["taxa"][0]["guid"]
            guid_in_taxonomies = taxonomies["guid"]
            guid_in_taxonomies_taxa = taxonomies["taxa"][0]["guid"]
            tool_component_guid_in_results_taxa = results["taxa"][0]["toolComponent"][
                "guid"
            ]
            guid_in_rules_relationships_target = rules["relationships"][0]["target"][
                "guid"
            ]
            guid_rules_relationship_target_tool_component = rules["relationships"][0][
                "target"
            ]["toolComponent"]["guid"]

            # guids are set according to this example:
            # https://github.com/microsoft/sarif-tutorials/blob/main/samples/3-Beyond-basics/standard-taxonomy.sarif
            self.assertTrue(
                guid_rules_relationship_target_tool_component
                == tool_component_guid_in_results_taxa
                == guid_in_taxonomies_taxa
            )
            self.assertTrue(
                guid_in_results_taxa
                == guid_in_taxonomies
                == guid_in_rules_relationships_target
            )
