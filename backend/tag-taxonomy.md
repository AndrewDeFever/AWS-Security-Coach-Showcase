# Canonical AWS Safety Coach tags

Backend stack deployments apply the canonical tag set at stack deploy time:

- `Project=AWSSafetyCoach`
- `AccountRole=Tool`
- `Environment=Dev|Prod`
- `Owner=PortfolioUser`
- `ManagedBy=Console`
- `Provisioned=IaC`
- `Purpose=Learning`

Resource-level tag declarations are intentionally avoided where stack tag propagation is sufficient. This prevents local resource tags from overriding canonical values such as `Environment=Dev|Prod` and avoids carrying legacy tags such as `CostCenter=Learning`.
