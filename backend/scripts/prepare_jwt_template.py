from pathlib import Path

SOURCE = Path("template.yaml")
OUTPUT = Path("template.generated.yaml")

PROHIBITED = (
    "ExpectedSharedSecret",
    "SharedSecretAuthorizer",
    "AuthorizerFunction",
    "x-safety-coach-secret",
    "EXPECTED_SHARED_SECRET",
    "CognitoIssuer:\n    Type: String",
    "CognitoAudience:\n    Type: String",
)

REQUIRED = (
    "Type: AWS::Cognito::UserPool",
    "Type: AWS::Cognito::UserPoolClient",
    "Type: AWS::Cognito::UserPoolDomain",
    "Type: AWS::Cognito::UserPoolGroup",
    "GroupName: operator",
    "GroupName: customer",
    "DefaultAuthorizer: CognitoJwtAuthorizer",
    "Path: /auth/targets",
    "Path: /auth/scan",
    "Path: /auth/scan/{scanId}",
    "Path: /auth/scan/{scanId}/status",
    "Path: /auth/report/{scanId}",
)


def main() -> None:
    template = SOURCE.read_text(encoding="utf-8")

    remaining = [value for value in PROHIBITED if value in template]
    if remaining:
        raise RuntimeError(
            f"Legacy or external auth configuration remains: {', '.join(remaining)}"
        )

    missing = [value for value in REQUIRED if value not in template]
    if missing:
        raise RuntimeError(
            f"Required stack-managed Cognito/JWT configuration missing: {', '.join(missing)}"
        )

    # Compatibility output for the existing deployment workflow. template.yaml is
    # now the authoritative deployable source; no authentication transformation occurs.
    OUTPUT.write_text(template, encoding="utf-8")
    print(f"Validated authoritative JWT template and copied it to {OUTPUT}")


if __name__ == "__main__":
    main()
