"""Deterministic multi-Region evaluator for public SSH/RDP security-group exposure."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

RULE = {
    "id": "ec2-security-groups-open-admin-ports",
    "service": "ec2",
    "control": "public-admin-ports",
    "version": "1.1",
}
MAX_REGION_WORKERS = 5


def _format_name_list(names: list[str], max_items: int = 10) -> str:
    shown = sorted(names)[:max_items]
    remaining = len(names) - len(shown)
    if remaining > 0:
        return ", ".join(shown) + f", and {remaining} more"
    return ", ".join(shown)


def _permission_allows_public_admin_port(permission: dict[str, Any]) -> list[str]:
    ip_protocol = str(permission.get("IpProtocol", "")).lower()
    if ip_protocol not in {"tcp", "-1"}:
        return []

    if ip_protocol == "-1":
        ports = [22, 3389]
    else:
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")
        if from_port is None or to_port is None:
            return []
        ports = []
        if int(from_port) <= 22 <= int(to_port):
            ports.append(22)
        if int(from_port) <= 3389 <= int(to_port):
            ports.append(3389)

    public_sources: list[str] = []
    for ip_range in permission.get("IpRanges", []):
        if ip_range.get("CidrIp") == "0.0.0.0/0":
            public_sources.append("0.0.0.0/0")
    for ipv6_range in permission.get("Ipv6Ranges", []):
        if ipv6_range.get("CidrIpv6") == "::/0":
            public_sources.append("::/0")

    return [
        f"tcp/{port} from {source}"
        for port in ports
        for source in public_sources
    ]


def _enabled_regions(discovery_client: Any) -> list[str]:
    response = discovery_client.describe_regions(AllRegions=False)
    regions: set[str] = set()
    for item in response.get("Regions", []):
        name = str(item.get("RegionName", "")).strip()
        opt_in_status = str(item.get("OptInStatus", "")).strip()
        if name and opt_in_status != "not-opted-in":
            regions.add(name)
    if not regions:
        raise RuntimeError("AWS returned no enabled Regions")
    return sorted(regions)


def _scan_region(region: str, client_for_region: Callable[[str], Any]) -> list[str]:
    client = client_for_region(region)
    open_rules: list[str] = []
    paginator = client.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for group in page.get("SecurityGroups", []):
            group_id = str(group.get("GroupId", "unknown"))
            group_name = str(group.get("GroupName", "unknown"))
            for permission in group.get("IpPermissions", []):
                for exposure in _permission_allows_public_admin_port(permission):
                    open_rules.append(
                        f"{region}: {group_name} ({group_id}): {exposure}"
                    )
    return sorted(open_rules)


def evaluate(
    discovery_client: Any,
    client_for_region: Callable[[str], Any],
) -> dict[str, Any]:
    """Evaluate the SSH/RDP exposure control across every enabled AWS Region."""
    try:
        regions = _enabled_regions(discovery_client)
    except Exception as error:
        return {
            "id": RULE["id"],
            "title": "Security group admin-port exposure check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": f"Runner could not discover the account's enabled AWS Regions: {str(error)}",
            "regionsEvaluated": [],
            "regionsUnavailable": [],
        }

    open_rules: list[str] = []
    evaluated_regions: list[str] = []
    unavailable_regions: list[str] = []
    workers = min(MAX_REGION_WORKERS, len(regions))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_scan_region, region, client_for_region): region
            for region in regions
        }
        for future in as_completed(futures):
            region = futures[future]
            try:
                open_rules.extend(future.result())
                evaluated_regions.append(region)
            except Exception:
                unavailable_regions.append(region)

    evaluated_regions.sort()
    unavailable_regions.sort()
    open_rules.sort()
    total_regions = len(regions)

    coverage = {
        "regionsEvaluated": evaluated_regions,
        "regionsUnavailable": unavailable_regions,
    }

    if open_rules:
        sample = _format_name_list(open_rules)
        details = (
            f"{len(open_rules)} public admin-port security group rules were found across "
            f"{len(evaluated_regions)} of {total_regions} enabled AWS Regions: {sample}."
        )
        if unavailable_regions:
            details += (
                " Coverage is incomplete because the following enabled Regions could not "
                f"be evaluated: {', '.join(unavailable_regions)}."
            )
        return {
            "id": RULE["id"],
            "title": "Security groups expose SSH or RDP to the internet",
            "severity": "HIGH",
            "status": "FAIL",
            "details": details,
            **coverage,
        }

    if unavailable_regions:
        return {
            "id": RULE["id"],
            "title": "Security group admin-port exposure check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": (
                f"No public SSH/RDP exposure was confirmed in {len(evaluated_regions)} of "
                f"{total_regions} enabled AWS Regions, but the control could not evaluate: "
                f"{', '.join(unavailable_regions)}."
            ),
            **coverage,
        }

    return {
        "id": RULE["id"],
        "title": "No security groups expose SSH or RDP to the internet",
        "severity": "INFO",
        "status": "PASS",
        "details": (
            f"No security groups across {total_regions} enabled AWS Regions allow inbound "
            "SSH or RDP from 0.0.0.0/0 or ::/0."
        ),
        **coverage,
    }
