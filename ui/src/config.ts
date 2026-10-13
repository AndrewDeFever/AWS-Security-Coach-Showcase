function requiredBuildVariable(name: string): string {
  const value = import.meta.env[name]?.trim();
  if (!value) throw new Error(`Missing required build variable ${name}`);
  return value;
}

export const API_BASE_URL = requiredBuildVariable("VITE_API_BASE_URL").replace(/\/+$/, "");
export const COGNITO_DOMAIN = requiredBuildVariable("VITE_COGNITO_DOMAIN").replace(/\/+$/, "");
export const COGNITO_AUTHORITY = requiredBuildVariable("VITE_COGNITO_AUTHORITY").replace(/\/+$/, "");
export const COGNITO_CLIENT_ID = requiredBuildVariable("VITE_COGNITO_CLIENT_ID");
export const COGNITO_REDIRECT_URI = requiredBuildVariable("VITE_COGNITO_REDIRECT_URI");
export const COGNITO_LOGOUT_URI = requiredBuildVariable("VITE_COGNITO_LOGOUT_URI");

export const IDEMPOTENCY_KEY_HEADER = "x-idempotency-key";
