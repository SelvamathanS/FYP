/**
 * Enterprise Authentication & Role-Based Access Control (RBAC) Engine
 * Protects CTI and GraphRAG API endpoints with JWT session verification and strict operational roles.
 */

import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

export type UserRole = 'VIEWER' | 'ANALYST' | 'ADMIN' | 'HACKER';

export interface AuthenticatedUser {
  userId: string;
  username: string;
  role: UserRole;
  issuedAt: number;
  expiresAt: number;
}

// Secret key management with production fail-fast validation
const DEFAULT_DEV_SECRET = 'cti-graphrag-dev-secret-key-32-chars-minimum!';
const isProduction = process.env.NODE_ENV === 'production';

let jwtSecret = process.env.JWT_SECRET;
if (isProduction && (!jwtSecret || jwtSecret === DEFAULT_DEV_SECRET || jwtSecret.length < 32)) {
  console.error('[FATAL SECURITY CONFIGURATION] In production mode, JWT_SECRET must be set and contain at least 32 characters.');
  process.exit(1);
} else if (!jwtSecret) {
  jwtSecret = DEFAULT_DEV_SECRET;
}

const JWT_SECRET_BUFFER = Buffer.from(jwtSecret, 'utf-8');

/**
 * Base64 URL encode
 */
function base64UrlEncode(str: string | Buffer): string {
  const buf = typeof str === 'string' ? Buffer.from(str, 'utf-8') : str;
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Base64 URL decode
 */
function base64UrlDecode(str: string): string {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) {
    b64 += '=';
  }
  return Buffer.from(b64, 'base64').toString('utf-8');
}

/**
 * Create a secure HMAC-SHA256 signature
 */
function signData(data: string): string {
  const hmac = crypto.createHmac('sha256', JWT_SECRET_BUFFER);
  hmac.update(data);
  return base64UrlEncode(hmac.digest());
}

/**
 * Issue a signed JWT token for a user session
 */
export function issueToken(username: string, role: UserRole, expiresInSeconds = 86400): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload: AuthenticatedUser = {
    userId: `usr_${crypto.createHash('md5').update(username).digest('hex').substring(0, 10)}`,
    username,
    role,
    issuedAt: now,
    expiresAt: now + expiresInSeconds
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = signData(`${encodedHeader}.${encodedPayload}`);

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

/**
 * Verify and decode a JWT token
 */
export function verifyToken(token: string): AuthenticatedUser | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [encodedHeader, encodedPayload, signature] = parts;
    const expectedSig = signData(`${encodedHeader}.${encodedPayload}`);

    // Timing-safe comparison to prevent timing side-channel attacks
    const sigBuf = Buffer.from(signature);
    const expBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }

    const payload: AuthenticatedUser = JSON.parse(base64UrlDecode(encodedPayload));
    const now = Math.floor(Date.now() / 1000);
    if (payload.expiresAt && payload.expiresAt < now) {
      return null; // Expired token
    }

    return payload;
  } catch (err) {
    return null;
  }
}

// Augment express request with user property
declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}

/**
 * Authentication Middleware: Extracts token from Authorization Bearer header or SecOps cookie/header
 */
export function authenticateToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization || (req.headers['x-secops-token'] as string);
  
  if (authHeader) {
    const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : authHeader;
    const user = verifyToken(token);
    if (user) {
      req.user = user;
      return next();
    }
  }

  // Fallback for development / non-production: generate or accept standard SecOps operator session
  if (!isProduction) {
    const roleHeader = (req.headers['x-secops-role'] as string) || 'ANALYST';
    const role: UserRole = ['ADMIN', 'ANALYST', 'HACKER', 'VIEWER'].includes(roleHeader.toUpperCase())
      ? (roleHeader.toUpperCase() as UserRole)
      : 'ANALYST';

    req.user = {
      userId: 'usr_secops_local',
      username: 'SecOps-Operator',
      role,
      issuedAt: Math.floor(Date.now() / 1000),
      expiresAt: Math.floor(Date.now() / 1000) + 86400
    };
    return next();
  }

  return res.status(401).json({
    status: 'error',
    error: 'AUTHENTICATION_REQUIRED',
    message: 'Valid Authorization: Bearer <token> required for this endpoint.'
  });
}

/**
 * Role-Based Access Control (RBAC) Guard Middleware
 */
export function requireRole(allowedRoles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        status: 'error',
        error: 'UNAUTHENTICATED',
        message: 'No active authenticated session found.'
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        status: 'error',
        error: 'FORBIDDEN_INSUFFICIENT_PERMISSIONS',
        message: `Role '${req.user.role}' is not authorized. Required: [${allowedRoles.join(', ')}].`
      });
    }

    return next();
  };
}
