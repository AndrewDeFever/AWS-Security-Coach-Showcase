# AWS Security Coach UI

The frontend is a React + TypeScript + Vite application for authenticated AWS posture assessments.

## Responsibilities

The UI provides:

- Cognito authorization-code + PKCE sign-in;
- operator and customer application views;
- customer connector onboarding;
- operator connector management;
- scan target selection and scan status;
- Management and Engineering report experiences;
- deterministic browser-generated PDF downloads; and
- legal/security boundary disclosures.

Authorization remains server-side. UI filtering is a usability feature, not a security boundary.

## Configuration

Build-time configuration is supplied through environment variables:

- `VITE_API_BASE_URL`
- `VITE_COGNITO_DOMAIN`
- `VITE_COGNITO_AUTHORITY`
- `VITE_COGNITO_CLIENT_ID`
- `VITE_COGNITO_REDIRECT_URI`
- `VITE_COGNITO_LOGOUT_URI`

The frontend must not contain AWS credentials, connector ExternalIds, customer role credentials, or private account-specific values.

See `../PUBLIC_CONFIGURATION.md` for public deployment placeholders and GitHub Environment configuration.

## Local validation

From `ui/`:

```bash
npm ci
npm run lint
npm run build
```

The build fails when required configuration is missing, and CI checks the generated bundle for prohibited account identifiers or retired secret references.

## Report model

The application supports four presentation contexts over shared normalized findings:

- managed Management
- managed Engineering
- self-service Management
- self-service Engineering

The managed and self-service experiences differ in delivery context, but they do not invent different security truth.
