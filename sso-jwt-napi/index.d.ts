export interface JwtOptions {
  /** Server profile name */
  server?: string;
  /** Environment within the server profile */
  env?: string;
  /** Override OAuth service URL (bypasses server profile) */
  oauthUrl?: string;
  /** Override token polling URL (separate from device authorization endpoint) */
  tokenUrl?: string;
  /** Override heartbeat URL */
  heartbeatUrl?: string;
  /** Override OAuth client ID */
  clientId?: string;
  /** Cache name for the encrypted token */
  cacheName?: string;
  /** Risk level 1-3 (1=low/24h, 2=medium/12h, 3=high/1h) */
  riskLevel?: number;
  /** Require biometric (Touch ID / Windows Hello) for each use */
  biometric?: boolean;
  /** Don't auto-open browser */
  noOpen?: boolean;
}

/** Obtain a JWT via OAuth Device Code flow with hardware-backed caching. */
export function getJwt(options?: JwtOptions | null): Promise<string>;
