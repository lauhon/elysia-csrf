import Elysia from "elysia";
import crypto from "node:crypto";

// Token generation utilities (ported from tokens.ts)
const EQUAL_GLOBAL_REGEXP = /=/g;
const PLUS_GLOBAL_REGEXP = /\+/g;
const SLASH_GLOBAL_REGEXP = /\//g;

/**
 * Hash a string with SHA256, returning url-safe base64.
 */
function hash(str: string): string {
  return crypto
    .createHash("sha256")
    .update(str, "ascii")
    .digest("base64")
    .replace(PLUS_GLOBAL_REGEXP, "-")
    .replace(SLASH_GLOBAL_REGEXP, "_")
    .replace(EQUAL_GLOBAL_REGEXP, "");
}

/**
 * Generate a random string of specified length
 */
function randomString(length: number): string {
  const bytes = crypto.randomBytes(Math.ceil(length * 0.75));
  return bytes
    .toString("base64")
    .replace(PLUS_GLOBAL_REGEXP, "-")
    .replace(SLASH_GLOBAL_REGEXP, "_")
    .replace(EQUAL_GLOBAL_REGEXP, "")
    .slice(0, length);
}

/**
 * Tokenize a secret and salt.
 */
function tokenize(secret: string, salt: string): string {
  return `${salt}-${hash(`${salt}-${secret}`)}`;
}

/**
 * Verify if a given token is valid for a given secret.
 */
function verifyToken(secret: string, token: string): boolean {
  if (!secret || typeof secret !== "string") {
    return false;
  }

  if (!token || typeof token !== "string") {
    return false;
  }

  const index = token.indexOf("-");

  if (index === -1) {
    return false;
  }

  const salt = token.slice(0, index);
  const expected = tokenize(secret, salt);

  // Constant-time comparison
  if (token.length !== expected.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < token.length; i++) {
    result |= token.charCodeAt(i) ^ expected.charCodeAt(i);
  }

  return result === 0;
}

/**
 * Generate a random secret synchronously
 */
function generateSecret(length: number = 18): string {
  const bytes = crypto.randomBytes(length);
  return bytes
    .toString("base64")
    .replace(PLUS_GLOBAL_REGEXP, "-")
    .replace(SLASH_GLOBAL_REGEXP, "_")
    .replace(EQUAL_GLOBAL_REGEXP, "");
}

type CookieOptions = {
  key?: string;
  domain?: string;
  httpOnly?: boolean;
  maxAge?: number;
  path?: string;
  sameSite?: "lax" | "none" | "strict" | boolean;
  secure?: boolean;
  signed?: boolean;
};

export type CsrfOptions = {
  /**
   * Cookie configuration. Set to true to enable cookie-based storage,
   * or provide detailed cookie options.
   * @default false
   */
  cookie?: boolean | CookieOptions;

  /**
   * HTTP methods to ignore (skip CSRF validation)
   * @default ["GET", "HEAD", "OPTIONS"]
   */
  ignoreMethods?: string[];

  /**
   * Custom function to extract CSRF token from request
   */
  value?: (context: any) => string | undefined;

  /**
   * Length of the salt used in token generation
   * @default 8
   */
  saltLength?: number;

  /**
   * Length of the secret used in token generation
   * @default 18
   */
  secretLength?: number;

  /**
   * Cookie secret for signed cookies (if using signed cookies)
   */
  secret?: string;
};

/**
 * Default value function to extract CSRF token from request
 */
function defaultValue(context: any): string | undefined {
  const { body, query, headers } = context;

  return (
    body?._csrf ||
    query?._csrf ||
    headers["csrf-token"] ||
    headers["xsrf-token"] ||
    headers["x-csrf-token"] ||
    headers["x-xsrf-token"]
  );
}

/**
 * Get cookie options with defaults
 */
function getCookieOptions(
  options: boolean | CookieOptions | undefined
): CookieOptions | undefined {
  if (options !== true && typeof options !== "object") {
    return undefined;
  }

  const defaults: CookieOptions = {
    key: "_csrf",
    path: "/",
    httpOnly: true,
    sameSite: "lax",
  };

  if (typeof options === "object") {
    return { ...defaults, ...options };
  }

  return defaults;
}

/**
 * Generate ignored methods lookup
 */
function getIgnoredMethods(methods: string[]): Record<string, true> {
  const obj: Record<string, true> = {};
  for (const method of methods) {
    obj[method.toUpperCase()] = true;
  }
  return obj;
}

/**
 * CSRF Protection Plugin for Elysia
 *
 * This plugin adds CSRF token generation and validation to protect against
 * Cross-Site Request Forgery attacks.
 */
export const csrf = (options: CsrfOptions = {}) => {
  const cookieConfig = getCookieOptions(options.cookie);
  const saltLength = options.saltLength ?? 8;
  const secretLength = options.secretLength ?? 18;
  const ignoreMethods = options.ignoreMethods ?? ["GET", "HEAD", "OPTIONS"];
  const ignoreMethod = getIgnoredMethods(ignoreMethods);
  const getValue = options.value ?? defaultValue;

  const cookieKey = cookieConfig?.key ?? "_csrf";
  const secretKey = options.secret ?? "csrfSecret";

  return new Elysia({
    name: "csrf",
  })
    .derive({ as: "global" }, ({ cookie }) => {
      let secret: string | undefined;
      let token: string | undefined;

      // Helper to set cookie attributes
      const setCookieAttributes = (cookieValue: any) => {
        if (cookieConfig?.path) cookieValue.path = cookieConfig.path;
        if (cookieConfig?.httpOnly !== undefined)
          cookieValue.httpOnly = cookieConfig.httpOnly;
        if (cookieConfig?.sameSite)
          cookieValue.sameSite = cookieConfig.sameSite;
        if (cookieConfig?.secure !== undefined)
          cookieValue.secure = cookieConfig.secure;
        if (cookieConfig?.maxAge) cookieValue.maxAge = cookieConfig.maxAge;
        if (cookieConfig?.domain) cookieValue.domain = cookieConfig.domain;
      };

      // Get or generate secret
      if (cookieConfig) {
        // Cookie-based storage - get current value
        const currentValue = (cookie as any)[cookieKey]?.value;
        secret = currentValue ? String(currentValue) : undefined;

        if (!secret) {
          secret = generateSecret(secretLength);
          // Set cookie with all attributes
          (cookie as any)[cookieKey].value = secret;
          setCookieAttributes((cookie as any)[cookieKey]);
        }
      }

      // Token generation function
      const csrfToken = (): string => {
        if (!cookieConfig) {
          throw new Error("CSRF: Cookie storage must be enabled");
        }

        let currentSecret = secret;

        if (!currentSecret) {
          currentSecret = generateSecret(secretLength);
          (cookie as any)[cookieKey].value = currentSecret;
          setCookieAttributes((cookie as any)[cookieKey]);
          secret = currentSecret;
        }

        // Use cached token if secret hasn't changed
        if (token && currentSecret === secret) {
          return token;
        }

        // Generate new token
        const salt = randomString(saltLength);
        token = tokenize(currentSecret, salt);

        return token;
      };

      return {
        csrfToken,
      };
    })
    .onBeforeHandle(
      { as: "global" },
      async ({ request, cookie, body, query }) => {
        const method = request.method.toUpperCase();

        // Skip verification for ignored methods
        if (ignoreMethod[method]) {
          return;
        }

        // Get secret from cookie
        let secret: string | undefined;
        if (cookieConfig) {
          const cookieValue = (cookie as any)[cookieKey]?.value;
          secret = cookieValue ? String(cookieValue) : undefined;
        }

        if (!secret) {
          return new Response("Invalid CSRF token", { status: 403 });
        }

        // Get token from request
        const tokenValue = getValue({
          body,
          query,
          headers: request.headers,
          cookie,
          request,
        });

        // Verify token
        if (!tokenValue || !verifyToken(secret, tokenValue)) {
          return new Response("Invalid CSRF token", { status: 403 });
        }
      }
    );
};
