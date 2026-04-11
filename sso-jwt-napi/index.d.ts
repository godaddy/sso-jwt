export interface JwtOptions {
  /** SSO environment: "dev", "test", "ote", "prod" */
  env?: string;
  /** Override OAuth service URL */
  oauthUrl?: string;
  /** Cache name for the encrypted token */
  cacheName?: string;
  /** Risk level 1-3 (1=low/24h, 2=medium/12h, 3=high/1h) */
  riskLevel?: number;
  /** Require biometric (Touch ID / Windows Hello) for each use */
  biometric?: boolean;
  /** Don't auto-open browser */
  noOpen?: boolean;
}

/**
 * Obtain an SSO JWT, authenticating via the OAuth Device Code flow if needed.
 *
 * Returns a cached token if one exists and is still valid.
 * Proactively refreshes tokens approaching expiration via the SSO heartbeat.
 * Falls back to full browser-based re-authentication when necessary.
 *
 * Drop-in replacement for `sso-jwt-legacy`'s `getJwt()`.
 */
export function getJwt(options?: JwtOptions | null): Promise<string>;
