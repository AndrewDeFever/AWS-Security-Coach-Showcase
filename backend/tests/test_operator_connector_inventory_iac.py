import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "template.yaml").read_text(encoding="utf-8")


class OperatorConnectorInventoryIaCTests(unittest.TestCase):
    def test_get_connectors_route_is_declared(self):
        self.assertIn("ListConnectorsRoute:", TEMPLATE)
        route_section = TEMPLATE.split("ListConnectorsRoute:", 1)[1].split(
            "CreateConnectorRoute:", 1
        )[0]
        self.assertIn("Path: /auth/connectors", route_section)
        self.assertIn("Method: GET", route_section)

    def test_scan_function_query_is_bounded_to_management_index(self):
        self.assertIn("Sid: ReadConnectorManagementIndex", TEMPLATE)
        section = TEMPLATE.split("Sid: ReadConnectorManagementIndex", 1)[1].split(
            "Sid: DisableConnectorMembershipsOnRevoke", 1
        )[0]
        self.assertIn("- dynamodb:Query", section)
        self.assertIn(
            "Resource: !Sub '${ConnectorsTable.Arn}/index/management-index'",
            section,
        )
        self.assertNotIn("dynamodb:Scan", section)
        self.assertNotIn("Resource: !GetAtt ConnectorsTable.Arn", section)


if __name__ == "__main__":
    unittest.main()
