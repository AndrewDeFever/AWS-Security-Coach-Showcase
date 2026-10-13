#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="${ROOT_DIR}/connector/template.yaml"

if [[ ! -f "${TEMPLATE}" ]]; then
  echo "ERROR: template not found: ${TEMPLATE}" >&2
  exit 1
fi

python3 - "${TEMPLATE}" <<'PY'
import pathlib
import sys

try:
    import yaml
except ImportError as exc:
    raise SystemExit("ERROR: PyYAML is required for structural verification") from exc

path = pathlib.Path(sys.argv[1])


class CloudFormationLoader(yaml.SafeLoader):
    pass


def _ref(loader, node):
    return {"Ref": loader.construct_scalar(node)}


def _getatt(loader, node):
    return {"Fn::GetAtt": loader.construct_scalar(node).split(".")}


CloudFormationLoader.add_constructor("!Ref", _ref)
CloudFormationLoader.add_constructor("!GetAtt", _getatt)

template = yaml.load(path.read_text(encoding="utf-8"), Loader=CloudFormationLoader)
if not isinstance(template, dict):
    raise SystemExit("ERROR: template root must be an object")

expected_template_version = "1.1.0"
required_actions = {
    "iam:GenerateCredentialReport",
    "iam:GetCredentialReport",
    "iam:GetAccountSummary",
    "iam:ListUsers",
    "iam:ListMFADevices",
    "iam:GetAccountPasswordPolicy",
    "cloudtrail:DescribeTrails",
    "s3:GetAccountPublicAccessBlock",
    "ec2:DescribeRegions",
    "ec2:DescribeSecurityGroups",
}

metadata = template.get("Metadata", {}).get("AWSSecurityCoach", {})
if metadata.get("ConnectorTemplateVersion") != expected_template_version:
    raise SystemExit(
        f"ERROR: connector template metadata version must be {expected_template_version}"
    )

parameters = template.get("Parameters", {})
if set(parameters) != {"TrustedScannerRoleArn", "ExternalId", "HomeRegion"}:
    raise SystemExit(
        "ERROR: connector template parameters must be exactly TrustedScannerRoleArn, "
        "ExternalId, and HomeRegion"
    )

external_id = parameters.get("ExternalId", {})
if external_id.get("NoEcho") is not True:
    raise SystemExit("ERROR: ExternalId must use NoEcho: true")
if int(external_id.get("MinLength", 0)) < 32:
    raise SystemExit("ERROR: ExternalId MinLength must be at least 32")

home_region = parameters.get("HomeRegion", {})
if home_region.get("Default") != "us-east-1":
    raise SystemExit("ERROR: HomeRegion must default to us-east-1")
if home_region.get("AllowedValues") != ["us-east-1"]:
    raise SystemExit("ERROR: HomeRegion must remain bounded to us-east-1")

resources = template.get("Resources", {})
if set(resources) != {"AWSSecurityCoachReadOnlyRole"}:
    raise SystemExit(
        "ERROR: connector template must contain exactly one resource named "
        "AWSSecurityCoachReadOnlyRole"
    )

role = resources["AWSSecurityCoachReadOnlyRole"]
if role.get("Type") != "AWS::IAM::Role":
    raise SystemExit("ERROR: the only resource must be AWS::IAM::Role")

properties = role.get("Properties", {})
if "RoleName" in properties:
    raise SystemExit("ERROR: RoleName must be CloudFormation-generated")
if properties.get("Path") != "/aws-security-coach/":
    raise SystemExit("ERROR: connector role path must be /aws-security-coach/")
if properties.get("MaxSessionDuration") != 3600:
    raise SystemExit("ERROR: connector role maximum session duration must be 3600 seconds")
if properties.get("Tags") != [
    {"Key": "AWSSecurityCoachConnector", "Value": "true"}
]:
    raise SystemExit(
        "ERROR: connector role must carry only AWSSecurityCoachConnector=true in this package"
    )

trust = properties.get("AssumeRolePolicyDocument", {})
trust_statements = trust.get("Statement", [])
if not isinstance(trust_statements, list) or len(trust_statements) != 1:
    raise SystemExit("ERROR: trust policy must contain exactly one statement")

trust_statement = trust_statements[0]
if trust_statement.get("Effect") != "Allow":
    raise SystemExit("ERROR: trust statement must use Effect Allow")
if trust_statement.get("Action") != "sts:AssumeRole":
    raise SystemExit("ERROR: trust action must be exactly sts:AssumeRole")
if trust_statement.get("Principal") != {"AWS": {"Ref": "TrustedScannerRoleArn"}}:
    raise SystemExit(
        "ERROR: trust principal must be !Ref TrustedScannerRoleArn and nothing broader"
    )
if trust_statement.get("Condition") != {
    "StringEquals": {"sts:ExternalId": {"Ref": "ExternalId"}}
}:
    raise SystemExit("ERROR: trust policy must require the ExternalId parameter")

policies = properties.get("Policies", [])
if not isinstance(policies, list) or len(policies) != 1:
    raise SystemExit("ERROR: connector role must have exactly one inline policy")

statements = policies[0].get("PolicyDocument", {}).get("Statement", [])
if not isinstance(statements, list):
    raise SystemExit("ERROR: permissions policy statements must be a list")

actual_actions = set()
for statement in statements:
    if statement.get("Effect") != "Allow":
        raise SystemExit("ERROR: every permissions statement must use Effect Allow")
    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    if not isinstance(actions, list):
        raise SystemExit("ERROR: statement Action must be a string or list")
    actual_actions.update(actions)

if actual_actions != required_actions:
    missing = sorted(required_actions - actual_actions)
    unexpected = sorted(actual_actions - required_actions)
    details = []
    if missing:
        details.append("missing=" + ", ".join(missing))
    if unexpected:
        details.append("unexpected=" + ", ".join(unexpected))
    raise SystemExit("ERROR: action set mismatch: " + "; ".join(details))

regional_statement = next(
    (s for s in statements if s.get("Sid") == "DiscoverEnabledRegionsAndSecurityGroups"),
    None,
)
if regional_statement is None:
    raise SystemExit("ERROR: DiscoverEnabledRegionsAndSecurityGroups statement is missing")
if set(regional_statement.get("Action", [])) != {
    "ec2:DescribeRegions",
    "ec2:DescribeSecurityGroups",
}:
    raise SystemExit("ERROR: regional EC2 statement must contain only region discovery and security-group reads")
if regional_statement.get("Resource") != "*":
    raise SystemExit("ERROR: EC2 discovery reads must use Resource '*'")
if "Condition" in regional_statement:
    raise SystemExit("ERROR: enabled-Region security-group reads must not be constrained to HomeRegion")

outputs = template.get("Outputs", {})
if set(outputs) != {
    "ConnectorRoleArn",
    "ConnectorRoleName",
    "HomeRegion",
    "ConnectorTemplateVersion",
}:
    raise SystemExit(
        "ERROR: connector outputs must be exactly ConnectorRoleArn, ConnectorRoleName, "
        "HomeRegion, and ConnectorTemplateVersion"
    )
if any("ExternalId" in str(value) for value in outputs.values()):
    raise SystemExit("ERROR: ExternalId must not appear in stack outputs")
if outputs["ConnectorTemplateVersion"].get("Value") != expected_template_version:
    raise SystemExit(
        f"ERROR: ConnectorTemplateVersion output must be {expected_template_version}"
    )

print("PASS: connector template version is exactly 1.1.0")
print("PASS: customer inputs are limited to scanner ARN, ExternalId, and HomeRegion")
print("PASS: template contains exactly one CloudFormation-generated IAM role")
print("PASS: connector role uses /aws-security-coach/ path and required connector tag")
print("PASS: trust policy allows only the supplied scanner-role ARN with ExternalId")
print("PASS: permissions equal the approved ten-action read-only set")
print("PASS: EC2 permissions allow enabled-Region discovery and security-group reads")
print("PASS: ExternalId is NoEcho and absent from outputs")
print("PASS: connector outputs expose only role ARN/name, HomeRegion, and template version")
PY

if command -v cfn-lint >/dev/null 2>&1; then
  cfn-lint "${TEMPLATE}"
else
  echo "NOTE: cfn-lint is not installed; skipped schema lint"
fi
