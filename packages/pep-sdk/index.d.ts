export interface PepOptions {
  issuerUrl: string;
  jwksPath?: string;
  verifyGrantPath?: string;
  jwksTtlMs?: number;
  algorithms?: string[];
  requireTenant?: boolean;
  fetchImpl?: typeof fetch;
}

export interface AccessClaims {
  sub: string;
  role?: string;
  tid?: string;
  tenant_id?: string;
  type?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  [key: string]: unknown;
}

export declare class PepClient {
  constructor(opts: PepOptions);
  verifyAccessToken(token: string, opts?: { audience?: string; issuer?: string }): Promise<AccessClaims>;
  verifyAccessGrant(args: {
    grantId: string;
    subject?: string;
    resource?: string;
    permission?: string;
    bearerToken?: string;
  }): Promise<Record<string, unknown>>;
  express(gate?: {
    roles?: string[];
    permission?: string;
    requireTenant?: boolean;
    issuer?: string;
    audience?: string;
  }): (req: any, res: any, next: any) => Promise<void>;
  envoyCheck(req: { headers: Record<string, string>; path?: string }): Promise<Record<string, unknown>>;
}

export function createPep(opts: PepOptions): PepClient;
