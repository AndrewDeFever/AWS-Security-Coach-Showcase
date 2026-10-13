import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "runner" / "regional_security_group_rule.py"
spec = importlib.util.spec_from_file_location("regional_security_group_rule_test", MODULE_PATH)
rule = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(rule)


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self):
        return iter(self.pages)


class FakeEc2:
    def __init__(self, *, regions=None, pages=None, error=None):
        self.regions = regions or []
        self.pages = pages or []
        self.error = error

    def describe_regions(self, **kwargs):
        if self.error:
            raise self.error
        self.last_describe_regions = kwargs
        return {"Regions": self.regions}

    def get_paginator(self, name):
        if self.error:
            raise self.error
        if name != "describe_security_groups":
            raise AssertionError(name)
        return FakePaginator(self.pages)


class MultiRegionSecurityGroupTests(unittest.TestCase):
    def test_passes_only_after_all_enabled_regions_are_checked(self):
        discovery = FakeEc2(
            regions=[
                {"RegionName": "us-west-2", "OptInStatus": "opt-in-not-required"},
                {"RegionName": "ap-east-1", "OptInStatus": "not-opted-in"},
                {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
            ]
        )
        clients = {
            "us-east-1": FakeEc2(pages=[{"SecurityGroups": []}]),
            "us-west-2": FakeEc2(pages=[{"SecurityGroups": []}]),
        }

        result = rule.evaluate(discovery, clients.__getitem__)

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["regionsEvaluated"], ["us-east-1", "us-west-2"])
        self.assertEqual(result["regionsUnavailable"], [])
        self.assertIn("across 2 enabled AWS Regions", result["details"])
        self.assertEqual(discovery.last_describe_regions, {"AllRegions": False})

    def test_aggregates_ranges_all_traffic_ipv4_and_ipv6_with_region_evidence(self):
        discovery = FakeEc2(
            regions=[
                {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
                {"RegionName": "us-west-2", "OptInStatus": "opt-in-not-required"},
            ]
        )
        east = FakeEc2(
            pages=[
                {
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-east",
                            "GroupName": "range-admin",
                            "IpPermissions": [
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 20,
                                    "ToPort": 30,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                    "Ipv6Ranges": [],
                                }
                            ],
                        }
                    ]
                }
            ]
        )
        west = FakeEc2(
            pages=[
                {
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-west",
                            "GroupName": "all-traffic",
                            "IpPermissions": [
                                {
                                    "IpProtocol": "-1",
                                    "IpRanges": [],
                                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                                }
                            ],
                        }
                    ]
                }
            ]
        )

        result = rule.evaluate(
            discovery,
            {"us-east-1": east, "us-west-2": west}.__getitem__,
        )

        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["severity"], "HIGH")
        self.assertIn("us-east-1: range-admin (sg-east): tcp/22 from 0.0.0.0/0", result["details"])
        self.assertIn("us-west-2: all-traffic (sg-west): tcp/22 from ::/0", result["details"])
        self.assertIn("us-west-2: all-traffic (sg-west): tcp/3389 from ::/0", result["details"])

    def test_incomplete_coverage_cannot_return_pass(self):
        discovery = FakeEc2(
            regions=[
                {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
                {"RegionName": "us-west-2", "OptInStatus": "opt-in-not-required"},
            ]
        )
        clients = {
            "us-east-1": FakeEc2(pages=[{"SecurityGroups": []}]),
            "us-west-2": FakeEc2(error=RuntimeError("region unavailable")),
        }

        result = rule.evaluate(discovery, clients.__getitem__)

        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["regionsEvaluated"], ["us-east-1"])
        self.assertEqual(result["regionsUnavailable"], ["us-west-2"])

    def test_confirmed_exposure_remains_fail_when_another_region_is_unavailable(self):
        discovery = FakeEc2(
            regions=[
                {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
                {"RegionName": "us-west-2", "OptInStatus": "opt-in-not-required"},
            ]
        )
        east = FakeEc2(
            pages=[
                {
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-open",
                            "GroupName": "open-ssh",
                            "IpPermissions": [
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 22,
                                    "ToPort": 22,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                    "Ipv6Ranges": [],
                                }
                            ],
                        }
                    ]
                }
            ]
        )
        west = FakeEc2(error=RuntimeError("region unavailable"))

        result = rule.evaluate(
            discovery,
            {"us-east-1": east, "us-west-2": west}.__getitem__,
        )

        self.assertEqual(result["status"], "FAIL")
        self.assertIn("Coverage is incomplete", result["details"])
        self.assertEqual(result["regionsUnavailable"], ["us-west-2"])

    def test_region_discovery_failure_returns_error(self):
        result = rule.evaluate(
            FakeEc2(error=RuntimeError("denied")),
            lambda region: None,
        )
        self.assertEqual(result["status"], "ERROR")
        self.assertIn("discover", result["details"])


if __name__ == "__main__":
    unittest.main()
