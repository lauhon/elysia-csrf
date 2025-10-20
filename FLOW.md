# CSRF Protection Flow Diagram

## Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Elysia CSRF Plugin                               │
│                                                                       │
│  Input: HTTP Request                                                 │
│  Output: Allow (200) or Deny (403)                                  │
│                                                                       │
│  Security: Token-based validation with cookie-stored secrets        │
└─────────────────────────────────────────────────────────────────────┘
```

## Flow 1: First Request (Token Generation)

```
┌──────────┐
│ Browser  │
└────┬─────┘
     │
     │ GET /form
     │
     ▼
┌─────────────────────────────────────────────────┐
│ Elysia Server                                    │
│                                                  │
│  1. Check for secret in cookie                  │
│     └─► None found                              │
│                                                  │
│  2. Generate random secret                      │
│     └─► crypto.randomBytes(18)                  │
│     └─► Result: "xK3m...9pLq" (base64)          │
│                                                  │
│  3. Store secret in cookie                      │
│     └─► Set-Cookie: _csrf=xK3m...9pLq           │
│         Path=/; HttpOnly; SameSite=Lax          │
│                                                  │
│  4. Generate token (when csrfToken() called)    │
│     ├─► Generate random salt: "aB12cD34"        │
│     ├─► Hash: SHA256(salt + secret)             │
│     └─► Token: "aB12cD34-kL9m...pQ8r"           │
└────────┬────────────────────────────────────────┘
         │
         │ HTTP 200 OK
         │ Set-Cookie: _csrf=xK3m...9pLq
         │ Body: <form>
         │       <input name="_csrf" value="aB12cD34-kL9m...pQ8r">
         │
         ▼
    ┌──────────┐
    │ Browser  │ Stores cookie + token
    └──────────┘
```

## Flow 2: Subsequent Request (Validation)

```
    ┌──────────┐
    │ Browser  │
    └────┬─────┘
         │
         │ POST /submit
         │ Cookie: _csrf=xK3m...9pLq
         │ Body: _csrf=aB12cD34-kL9m...pQ8r&message=hello
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Elysia Server - CSRF Validation                             │
│                                                              │
│  1. Check HTTP method                                       │
│     ├─► POST (not ignored)                                  │
│     └─► Continue validation ✓                              │
│                                                              │
│  2. Extract secret from cookie                              │
│     ├─► Cookie: _csrf=xK3m...9pLq                           │
│     └─► Secret: "xK3m...9pLq" ✓                            │
│                                                              │
│  3. Extract token from request                              │
│     ├─► Check body._csrf                                    │
│     ├─► Check query._csrf                                   │
│     ├─► Check headers['x-csrf-token']                       │
│     └─► Found: "aB12cD34-kL9m...pQ8r" ✓                    │
│                                                              │
│  4. Parse token                                             │
│     ├─► Split on '-'                                        │
│     ├─► Salt: "aB12cD34"                                    │
│     └─► Hash: "kL9m...pQ8r"                                 │
│                                                              │
│  5. Verify token                                            │
│     ├─► Compute expected: SHA256(salt + secret)            │
│     ├─► Expected hash: "kL9m...pQ8r"                        │
│     ├─► Compare: token_hash === expected_hash              │
│     │   (constant-time comparison)                          │
│     └─► Match! ✓                                           │
│                                                              │
│  6. Validation passed                                       │
│     └─► Continue to route handler                          │
└────────┬────────────────────────────────────────────────────┘
         │
         │ HTTP 200 OK
         │ Body: {"success": true, "message": "hello"}
         │
         ▼
    ┌──────────┐
    │ Browser  │
    └──────────┘
```

## Flow 3: Attack Scenario (Blocked)

```
    ┌───────────┐
    │ Attacker  │ (malicious website)
    └─────┬─────┘
          │
          │ POST /submit
          │ Cookie: (none or attacker's own)
          │ Body: _csrf=FAKE_TOKEN&message=attack
          │
          ▼
┌──────────────────────────────────────────────────┐
│ Elysia Server - CSRF Validation                  │
│                                                   │
│  1. Check HTTP method                            │
│     └─► POST (not ignored) ✓                    │
│                                                   │
│  2. Extract secret from cookie                   │
│     └─► ❌ No cookie or wrong secret             │
│         OR                                        │
│     └─► Secret doesn't match attacker's token   │
│                                                   │
│  3. Extract token                                │
│     └─► "FAKE_TOKEN"                            │
│                                                   │
│  4. Verify token                                 │
│     ├─► Compute: SHA256(salt + secret)          │
│     └─► ❌ MISMATCH                              │
│                                                   │
│  5. Validation FAILED                            │
│     └─► Return 403 Forbidden                    │
└────────┬─────────────────────────────────────────┘
         │
         │ HTTP 403 Forbidden
         │ Body: "Invalid CSRF token"
         │
         ▼
    ┌───────────┐
    │ Attacker  │ ❌ Attack blocked!
    └───────────┘
```

## Security Layers

```
Layer 1: Cookie-based Secret
├─► Unique per user session
├─► HttpOnly (no JavaScript access)
├─► SameSite=Lax (CSRF protection)
└─► Secure flag for HTTPS

Layer 2: Salted Token
├─► Random salt per token
├─► SHA-256 cryptographic hash
├─► URL-safe base64 encoding
└─► Can't be guessed or forged

Layer 3: Constant-time Comparison
├─► Prevents timing attacks
├─► Equal-length comparison only
└─► No early exit on mismatch

Layer 4: Method Filtering
├─► Safe methods (GET, HEAD) skip validation
├─► Only state-changing methods checked
└─► Configurable method list
```

## Token Structure

```
Token Format:
┌──────────┬───┬────────────────────────────────────────┐
│   Salt   │ - │              Hash                      │
├──────────┼───┼────────────────────────────────────────┤
│ aB12cD34 │ - │ kL9m...pQ8r                            │
└──────────┴───┴────────────────────────────────────────┘
    8 chars   separator   43 chars (base64 SHA-256)

Generation:
Salt = randomString(8)
Hash = base64(SHA256(Salt + Secret))
Token = Salt + "-" + Hash

Verification:
[Salt, Hash] = Token.split("-")
Expected = base64(SHA256(Salt + Secret))
Valid = (Hash === Expected)  // constant-time compare
```

## Configuration Options

```
csrf({
  cookie: {
    key: "_csrf",           // Cookie name
    httpOnly: true,         // Prevent XSS
    secure: true,           // HTTPS only
    sameSite: "strict",     // CSRF protection
    maxAge: 3600,           // 1 hour
    domain: "example.com"   // Cookie domain
  },

  ignoreMethods: [          // Skip validation
    "GET", "HEAD", "OPTIONS"
  ],

  value: (ctx) => {         // Custom extraction
    return ctx.body?._csrf
        || ctx.headers["x-csrf-token"];
  },

  saltLength: 8,            // Salt length
  secretLength: 18          // Secret length
})
```

## Why This Works

```
Same-Origin Request (✓ Allowed):
1. Browser has cookie with secret
2. Website has token from previous GET
3. POST includes both cookie and token
4. Server verifies: token was generated from this secret
5. Request allowed

Cross-Origin Attack (✗ Blocked):
1. Attacker's site triggers POST
2. Browser sends cookie (if any)
3. But attacker doesn't know the token
4. Server verification fails
5. Request blocked with 403

The token proves the request came from a page
that previously received it from our server,
not from a random attacker site.
```
