# Tool-account governance configuration

This directory codifies account-level AWS Security Coach settings that are intentionally operated outside the application SAM stacks.

## CloudTrail retention

The tool account CloudTrail `tool-account-trail` writes to `aws-cloudtrail-logs-123456789012-example`.

The bucket is retained as an existing console-managed resource rather than being adopted into the backend CloudFormation/SAM stack. Its lifecycle policy is declared in `cloudtrail-lifecycle.json` and can be reapplied idempotently with `apply-cloudtrail-lifecycle.sh`.

Policy:

- retain CloudTrail objects for 365 days;
- expire objects after 365 days;
- do not transition objects to another storage class.

Apply from an authenticated shell in account `123456789012`:

```bash
bash infra/tool-account/apply-cloudtrail-lifecycle.sh
```

Optional overrides:

- `AWS_REGION` (default `us-east-1`)
- `CLOUDTRAIL_BUCKET_NAME` (default `aws-cloudtrail-logs-123456789012-example`)

The script prints the resulting lifecycle configuration after applying it so the deployed state can be verified immediately.
