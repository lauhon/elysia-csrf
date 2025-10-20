# Quick Start Guide

## Installation

```bash
bun add elysia-csrf
# or
npm install elysia-csrf
```

## Basic Usage (30 seconds)

```typescript
import { Elysia } from "elysia";
import { csrf } from "elysia-csrf";

const app = new Elysia()
  // 1. Add CSRF protection
  .use(csrf({ cookie: true }))

  // 2. Generate tokens in your routes
  .get("/form", ({ csrfToken }) => {
    return `
      <form method="POST" action="/submit">
        <input type="hidden" name="_csrf" value="${csrfToken()}" />
        <input type="text" name="message" />
        <button>Submit</button>
      </form>
    `;
  })

  // 3. Protected routes automatically validate tokens
  .post("/submit", ({ body }) => {
    return { success: true, message: body };
  })

  .listen(3000);
```

That's it! Your POST routes are now protected against CSRF attacks.

## How It Works

1. **`csrf({ cookie: true })`** - Enables CSRF protection
2. **`csrfToken()`** - Generates a unique token for each request
3. **Automatic validation** - POST/PUT/DELETE requests are automatically checked

## Common Patterns

### For HTML Forms

```typescript
.get("/", ({ csrfToken }) => {
  return `
    <form method="POST">
      <input name="_csrf" value="${csrfToken()}" type="hidden" />
      <!-- your form fields -->
    </form>
  `;
})
```

### For JSON APIs

```typescript
// Server: Provide token endpoint
.get("/api/token", ({ csrfToken }) => ({
  token: csrfToken()
}))

// Client: Include in header
fetch('/api/endpoint', {
  method: 'POST',
  headers: {
    'X-CSRF-Token': token,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(data)
})
```

### For Production (HTTPS)

```typescript
.use(csrf({
  cookie: {
    httpOnly: true,    // Prevent XSS
    secure: true,      // HTTPS only
    sameSite: "strict" // Prevent CSRF
  }
}))
```

## What Gets Protected?

- ✅ POST requests
- ✅ PUT requests
- ✅ DELETE requests
- ✅ PATCH requests

**Not protected** (by default):

- ❌ GET requests
- ❌ HEAD requests
- ❌ OPTIONS requests

## Troubleshooting

### "Invalid CSRF token" error?

1. **Check cookie is sent**: Make sure cookies are enabled
2. **Check token is included**: Verify `_csrf` in body/query/headers
3. **Check token is fresh**: Get a new token if page was open for long

### Token not working in fetch()?

```javascript
// ❌ Wrong - credentials not included
fetch("/api", { method: "POST" });

// ✅ Correct - include cookies
fetch("/api", {
  method: "POST",
  credentials: "include", // This!
});
```

## Next Steps

- 📖 Read [README.md](./README.md) for full documentation
- 🎯 See [examples-advanced.ts](./examples-advanced.ts) for advanced patterns
- 🧪 Run `bun run test.ts` to see tests
- 🌐 Run `bun run example.ts` for interactive demo

## Need Help?

Common questions:

**Q: Do I need to validate tokens manually?**  
A: No! The plugin automatically validates all non-GET requests.

**Q: Can I use custom headers instead of body fields?**  
A: Yes! Use `value` option or send `X-CSRF-Token` header.

**Q: Is this compatible with [framework]?**  
A: Yes! It's just HTTP. Works with any client that can send cookies and form data.

**Q: How secure is this?**  
A: Uses SHA-256 hashing, constant-time comparison, and follows OWASP recommendations.

## Quick Reference

```typescript
// Configure
csrf({
  cookie: true | {...options},      // Cookie config
  ignoreMethods: ['GET', 'HEAD'],   // Skip these methods
  value: (ctx) => string,           // Custom token extractor
  saltLength: 8,                    // Salt length
  secretLength: 18                  // Secret length
})

// Use in routes
({ csrfToken }) => csrfToken()      // Generate token
```

That's all you need to know to get started! 🚀
