#!/usr/bin/env bash
set -euo pipefail

stack_name="${1:?usage: apply_managed_login_branding.sh <backend-stack-name>}"
region="${AWS_REGION:-us-east-1}"
asset_path="${2:-../ui/public/managed-login-mark.svg}"

if [[ ! -f "$asset_path" ]]; then
  echo "Managed Login branding asset not found: $asset_path" >&2
  exit 1
fi

user_pool_id="$(aws cloudformation describe-stacks \
  --stack-name "$stack_name" \
  --region "$region" \
  --query "Stacks[0].Outputs[?OutputKey=='CognitoUserPoolId'].OutputValue | [0]" \
  --output text)"

client_id="$(aws cloudformation describe-stacks \
  --stack-name "$stack_name" \
  --region "$region" \
  --query "Stacks[0].Outputs[?OutputKey=='CognitoUserPoolClientId'].OutputValue | [0]" \
  --output text)"

if [[ -z "$user_pool_id" || "$user_pool_id" == "None" || -z "$client_id" || "$client_id" == "None" ]]; then
  echo "Unable to resolve Cognito User Pool/app client outputs from $stack_name" >&2
  exit 1
fi

branding_json="$(aws cognito-idp describe-managed-login-branding-by-client \
  --user-pool-id "$user_pool_id" \
  --client-id "$client_id" \
  --return-merged-resources \
  --region "$region" \
  --output json)"

branding_id="$(jq -r '.ManagedLoginBranding.ManagedLoginBrandingId // empty' <<<"$branding_json")"
if [[ -z "$branding_id" ]]; then
  echo "No existing Managed Login branding style is associated with app client $client_id" >&2
  exit 1
fi

settings_file="$(mktemp)"
assets_file="$(mktemp)"
trap 'rm -f "$settings_file" "$assets_file"' EXIT

jq '.ManagedLoginBranding.Settings
  | .categories.global.colorSchemeMode = "LIGHT"
  | .components.favicon.enabledTypes = ["SVG"]
  | .components.pageBackground.image.enabled = false
  | .components.pageBackground.lightMode.color = "06111fff"
  | .components.pageBackground.darkMode.color = "06111fff"
  | .components.form.lightMode.backgroundColor = "111827ff"
  | .components.form.lightMode.borderColor = "27364fff"
  | .components.form.darkMode.backgroundColor = "111827ff"
  | .components.form.darkMode.borderColor = "27364fff"
  | .components.form.logo.enabled = false
  | .components.pageText.lightMode.bodyColor = "cbd5e1ff"
  | .components.pageText.lightMode.descriptionColor = "94a3b8ff"
  | .components.pageText.lightMode.headingColor = "f8fafcff"
  | .components.pageText.darkMode.bodyColor = "cbd5e1ff"
  | .components.pageText.darkMode.descriptionColor = "94a3b8ff"
  | .components.pageText.darkMode.headingColor = "f8fafcff"
  | .componentClasses.inputLabel.lightMode.textColor = "f8fafcff"
  | .componentClasses.inputLabel.darkMode.textColor = "f8fafcff"
  | .componentClasses.inputDescription.lightMode.textColor = "cbd5e1ff"
  | .componentClasses.inputDescription.darkMode.textColor = "cbd5e1ff"
  | .components.primaryButton.lightMode.defaults.backgroundColor = "2563ebff"
  | .components.primaryButton.lightMode.defaults.textColor = "ffffffff"
  | .components.primaryButton.lightMode.hover.backgroundColor = "1d4ed8ff"
  | .components.primaryButton.lightMode.hover.textColor = "ffffffff"
  | .components.primaryButton.lightMode.active.backgroundColor = "1e40afff"
  | .components.primaryButton.lightMode.active.textColor = "ffffffff"
  | .components.primaryButton.darkMode.defaults.backgroundColor = "2563ebff"
  | .components.primaryButton.darkMode.defaults.textColor = "ffffffff"
  | .components.primaryButton.darkMode.hover.backgroundColor = "1d4ed8ff"
  | .components.primaryButton.darkMode.hover.textColor = "ffffffff"
  | .components.primaryButton.darkMode.active.backgroundColor = "1e40afff"
  | .components.primaryButton.darkMode.active.textColor = "ffffffff"' \
  <<<"$branding_json" > "$settings_file"

asset_base64="$(base64 -w 0 "$asset_path")"
jq -n --arg bytes "$asset_base64" '[
  {
    Category: "FAVICON_SVG",
    ColorMode: "DYNAMIC",
    Extension: "SVG",
    Bytes: $bytes
  },
  {
    Category: "FAVICON_SVG",
    ColorMode: "LIGHT",
    Extension: "SVG",
    Bytes: $bytes
  },
  {
    Category: "FAVICON_SVG",
    ColorMode: "DARK",
    Extension: "SVG",
    Bytes: $bytes
  }
]' > "$assets_file"

aws cognito-idp update-managed-login-branding \
  --user-pool-id "$user_pool_id" \
  --managed-login-branding-id "$branding_id" \
  --settings "file://$settings_file" \
  --assets "file://$assets_file" \
  --region "$region" \
  >/dev/null

verified="$(aws cognito-idp describe-managed-login-branding-by-client \
  --user-pool-id "$user_pool_id" \
  --client-id "$client_id" \
  --region "$region" \
  --output json)"

verified_summary="$(jq '{
  Id: .ManagedLoginBranding.ManagedLoginBrandingId,
  ColorScheme: .ManagedLoginBranding.Settings.categories.global.colorSchemeMode,
  FaviconTypes: .ManagedLoginBranding.Settings.components.favicon.enabledTypes,
  FaviconModes: [
    .ManagedLoginBranding.Assets[]
    | select(.Category == "FAVICON_SVG")
    | .ColorMode
  ] | sort,
  Page: .ManagedLoginBranding.Settings.components.pageBackground.lightMode.color,
  Form: .ManagedLoginBranding.Settings.components.form.lightMode.backgroundColor,
  FieldLabel: .ManagedLoginBranding.Settings.componentClasses.inputLabel.lightMode.textColor,
  FieldDescription: .ManagedLoginBranding.Settings.componentClasses.inputDescription.lightMode.textColor,
  Logo: .ManagedLoginBranding.Settings.components.form.logo.enabled
}' <<<"$verified")"

echo "Managed Login branding reconciled for $stack_name"
echo "$verified_summary"
