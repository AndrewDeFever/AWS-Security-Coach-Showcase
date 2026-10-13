import { useCallback, useEffect, useState } from "react";
import {
  COGNITO_AUTHORITY,
  COGNITO_CLIENT_ID,
  COGNITO_DOMAIN,
  COGNITO_LOGOUT_URI,
  COGNITO_REDIRECT_URI,
} from "./config";

const PKCE_VERIFIER_KEY = "aws-security-coach-pkce-verifier";
const OIDC_STATE_KEY = "aws-security-coach-oidc-state";

type TokenResponse = {
  access_token?: string;
  id_token?: string;
  token_type?: string;
  expires_in?: number;
};

type AuthState = {
  isLoading: boolean;
  isAuthenticated: boolean;
  accessToken: string;
  error: string;
  signIn: () => Promise<void>;
  signOut: () => void;
};

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function randomValue(length = 32): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return base64Url(bytes);
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64Url(new Uint8Array(digest));
}

function clearTransientAuthState() {
  sessionStorage.removeItem(PKCE_VERIFIER_KEY);
  sessionStorage.removeItem(OIDC_STATE_KEY);
}

function cleanCallbackUrl() {
  const url = new URL(window.location.href);
  url.searchParams.delete("code");
  url.searchParams.delete("state");
  url.searchParams.delete("error");
  url.searchParams.delete("error_description");
  window.history.replaceState({}, document.title, `/${url.search}${url.hash}`);
}

async function exchangeAuthorizationCode(code: string, verifier: string): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: COGNITO_CLIENT_ID,
    code,
    redirect_uri: COGNITO_REDIRECT_URI,
    code_verifier: verifier,
  });

  const response = await fetch(`${COGNITO_DOMAIN}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!response.ok) {
    throw new Error("Authentication could not be completed.");
  }

  return response.json() as Promise<TokenResponse>;
}

export function useOidcAuth(): AuthState {
  const [isLoading, setIsLoading] = useState(true);
  const [accessToken, setAccessToken] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;

    async function processCallback() {
      const url = new URL(window.location.href);
      const code = url.searchParams.get("code");
      const returnedState = url.searchParams.get("state");
      const providerError = url.searchParams.get("error");

      if (!code && !providerError) {
        if (active) setIsLoading(false);
        return;
      }

      try {
        if (providerError) throw new Error("Authentication was not completed.");

        const verifier = sessionStorage.getItem(PKCE_VERIFIER_KEY) ?? "";
        const expectedState = sessionStorage.getItem(OIDC_STATE_KEY) ?? "";
        if (!verifier || !expectedState || returnedState !== expectedState) {
          throw new Error("Authentication validation failed.");
        }

        const tokens = await exchangeAuthorizationCode(code ?? "", verifier);
        if (!tokens.access_token || tokens.token_type?.toLowerCase() !== "bearer") {
          throw new Error("Authentication did not return a usable access token.");
        }

        if (active) {
          setAccessToken(tokens.access_token);
          setError("");
        }
      } catch (caught: unknown) {
        if (active) {
          setAccessToken("");
          setError(caught instanceof Error ? caught.message : "Authentication could not be completed.");
        }
      } finally {
        clearTransientAuthState();
        cleanCallbackUrl();
        if (active) setIsLoading(false);
      }
    }

    void processCallback();
    return () => {
      active = false;
    };
  }, []);

  const signIn = useCallback(async () => {
    setError("");
    const verifier = randomValue(48);
    const state = randomValue(32);
    const challenge = await sha256(verifier);

    sessionStorage.setItem(PKCE_VERIFIER_KEY, verifier);
    sessionStorage.setItem(OIDC_STATE_KEY, state);

    const authorizeUrl = new URL(`${COGNITO_DOMAIN}/oauth2/authorize`);
    authorizeUrl.search = new URLSearchParams({
      response_type: "code",
      client_id: COGNITO_CLIENT_ID,
      redirect_uri: COGNITO_REDIRECT_URI,
      scope: "openid email",
      state,
      code_challenge_method: "S256",
      code_challenge: challenge,
    }).toString();

    window.location.assign(authorizeUrl.toString());
  }, []);

  const signOut = useCallback(() => {
    setAccessToken("");
    setError("");
    clearTransientAuthState();

    const logoutUrl = new URL(`${COGNITO_DOMAIN}/logout`);
    logoutUrl.search = new URLSearchParams({
      client_id: COGNITO_CLIENT_ID,
      logout_uri: COGNITO_LOGOUT_URI,
    }).toString();
    window.location.assign(logoutUrl.toString());
  }, []);

  return {
    isLoading,
    isAuthenticated: Boolean(accessToken),
    accessToken,
    error,
    signIn,
    signOut,
  };
}

export const OIDC_ISSUER = COGNITO_AUTHORITY;
