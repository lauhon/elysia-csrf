# Elysia CSRF

CSRF (Cross-Site Request Forgery) protection plugin for [Elysia](https://elysiajs.com/).

This plugin provides robust CSRF protection using token-based validation with cookie storage, ported from the battle-tested Express `csurf` middleware.

## Features

- 🔒 **Secure Token Generation**: Uses cryptographic hashing (SHA-256) for token creation
- 🍪 **Cookie-Based Storage**: Leverages Elysia's reactive cookie system
- ⚡ **Zero Dependencies**: All crypto operations use Node.js built-in modules
- 🎯 **Method Filtering**: Automatically skips validation for safe HTTP methods (GET, HEAD, OPTIONS)
- 🛠️ **Highly Configurable**: Customize cookie settings, token extraction, and more
- 📝 **TypeScript First**: Full type safety and IntelliSense support

## Installation

```bash
bun add elysia-csrf
```

## Quick Start

```typescript
import { Elysia } from "elysia";
import { csrf } from "elysia-csrf";

const app = new Elysia()
  .use(
    csrf({
      cookie: true, // Enable cookie-based storage with defaults
    })
  )
  .get("/form", ({ csrfToken }) => {
    const token = csrfToken();
    return `
      <form method="POST" action="/submit">
        <input type="hidden" name="_csrf" value="${token}" />
        <input type="text" name="data" />
        <button type="submit">Submit</button>
      </form>
    `;
  })
  .post("/submit", ({ body }) => {
    return { success: true, data: body };
  })
  .listen(3000);
```

## How It Works

1. **Secret Generation**: A random secret is generated and stored in a cookie
2. **Token Creation**: When `csrfToken()` is called, a token is created by hashing the secret with a random salt
3. **Token Validation**: On POST/PUT/DELETE requests, the plugin extracts the token and verifies it against the secret
4. **Constant-Time Comparison**: Token verification uses constant-time comparison to prevent timing attacks

## API

### `csrf(options?)`

Creates a CSRF protection plugin with the specified options.

#### Options

```typescript
type CsrfOptions = {
  // Cookie configuration
  cookie?:
    | boolean
    | {
        key?: string; // Cookie name (default: "_csrf")
        domain?: string; // Cookie domain
        httpOnly?: boolean; // HttpOnly flag (default: true)
        maxAge?: number; // Max age in seconds
        path?: string; // Cookie path (default: "/")
        sameSite?: "lax" | "none" | "strict" | boolean; // SameSite policy (default: "lax")
        secure?: boolean; // Secure flag
        signed?: boolean; // Enable cookie signing
      };

  // HTTP methods to skip validation (default: ["GET", "HEAD", "OPTIONS"])
  ignoreMethods?: string[];

  // Custom token extraction function
  value?: (context: any) => string | undefined;

  // Token generation options
  saltLength?: number; // Length of salt (default: 8)
  secretLength?: number; // Length of secret (default: 18)

  // Cookie signing secret
  secret?: string;
};
```

### Context Properties

When the plugin is installed, the following properties are available in route handlers:

#### `csrfToken()`

Function that generates and returns a CSRF token.

```typescript
app.get("/api/token", ({ csrfToken }) => {
  return { token: csrfToken() };
});
```

## Usage Examples

### Basic HTML Form

```typescript
app.get("/", ({ csrfToken }) => {
  return `
    <form method="POST" action="/submit">
      <input type="hidden" name="_csrf" value="${csrfToken()}" />
      <input type="text" name="message" />
      <button>Submit</button>
    </form>
  `;
});

app.post("/submit", ({ body }) => {
  return { message: "Success!" };
});
```

### JSON API with Custom Header

```typescript
app
  .use(
    csrf({
      cookie: true,
      value: ({ headers }) => headers["x-csrf-token"],
    })
  )
  .get("/api/token", ({ csrfToken }) => {
    return { csrfToken: csrfToken() };
  })
  .post("/api/data", ({ body }) => {
    return { success: true };
  });
```

Client-side JavaScript:

```javascript
// Get token first
const { csrfToken } = await fetch("/api/token").then((r) => r.json());

// Include token in subsequent requests
await fetch("/api/data", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrfToken,
  },
  body: JSON.stringify({ data: "example" }),
});
```

### Custom Cookie Configuration

```typescript
app.use(
  csrf({
    cookie: {
      key: "XSRF-TOKEN", // Custom cookie name
      path: "/",
      httpOnly: true,
      secure: true, // Enable for HTTPS
      sameSite: "strict",
      maxAge: 3600, // 1 hour
      domain: "example.com",
    },
  })
);
```

### Skip Validation for Specific Methods

```typescript
app.use(
  csrf({
    cookie: true,
    ignoreMethods: ["GET", "HEAD", "OPTIONS", "TRACE"],
  })
);
```

### Custom Token Extraction

```typescript
app.use(
  csrf({
    cookie: true,
    value: (context) => {
      // Check body first, then query, then headers
      return (
        context.body?._csrf ||
        context.query?.csrf ||
        context.headers["x-custom-csrf-token"]
      );
    },
  })
);
```

## Token Extraction

By default, the plugin looks for the CSRF token in the following locations (in order):

1. `body._csrf` - Request body field
2. `query._csrf` - Query string parameter
3. `headers['csrf-token']` - CSRF-Token header
4. `headers['xsrf-token']` - XSRF-Token header
5. `headers['x-csrf-token']` - X-CSRF-Token header
6. `headers['x-xsrf-token']` - X-XSRF-Token header

You can customize this behavior using the `value` option.

## Security Considerations

1. **Always use HTTPS in production** - Set `secure: true` in cookie options
2. **Use HttpOnly cookies** - Prevents XSS attacks from stealing tokens (enabled by default)
3. **Set appropriate SameSite policy** - "strict" or "lax" recommended (default: "lax")
4. **Rotate secrets regularly** - Consider implementing secret rotation for long-lived applications
5. **Don't expose tokens in URLs** - Always use POST bodies or headers

## Error Handling

When CSRF validation fails, the plugin returns a `403 Forbidden` response with the message "Invalid CSRF token".

You can customize error handling using Elysia's error handling mechanisms:

```typescript
app.use(csrf({ cookie: true })).onError(({ code, error, set }) => {
  if (error.message === "Invalid CSRF token") {
    set.status = 403;
    return { error: "CSRF validation failed" };
  }
});
```

## Migration from Express csurf

This plugin provides similar functionality to Express's `csurf` middleware:

**Express:**

```javascript
const csurf = require("csurf");
app.use(csurf({ cookie: true }));
app.get("/form", (req, res) => {
  res.send(`<input name="_csrf" value="${req.csrfToken()}">`);
});
```

**Elysia:**

```typescript
import { csrf } from "elysia-csrf";
app.use(csrf({ cookie: true }));
app.get("/form", ({ csrfToken }) => {
  return `<input name="_csrf" value="${csrfToken()}">`;
});
```

## Development

To run the example:

```bash
bun run example.ts
```

Then visit http://localhost:3000 to see the CSRF protection in action.

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
