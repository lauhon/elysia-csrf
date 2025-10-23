<div  style="display: flex; gap: 1rem; justify-content: center;">

[![build](https://img.shields.io/github/actions/workflow/status/lauhon/elysia-csrf/ci.yml?branch=main&style=flat-square)](https://github.com/lauhon/elysia-csrf/actions)

[![npm version](https://img.shields.io/npm/v/elysia-csrf.svg)](https://www.npmjs.com/package/elysia-csrf)

[![license](https://img.shields.io/npm/l/elysia-csrf.svg)](https://github.com/lauhon/elysia-csrf/blob/main/LICENSE)

</div>

# Elysia CSRF

CSRF (Cross-Site Request Forgery) protection plugin for [Elysia](https://elysiajs.com/).

## Installation

```bash
bun add elysia-csrf
```

## Quick Start

```typescript
import { Elysia } from "elysia";
import { csrf } from "elysia-csrf";

const app = new Elysia()
  .use(csrf({ cookie: true }))
  .get("/form", ({ csrfToken }) => {
    return `
      <form method="POST" action="/submit">
        <input type="hidden" name="_csrf" value="${csrfToken()}" />
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

## Configuration

```typescript
csrf({
  cookie?: boolean | {
    key?: string;        // Cookie name (default: "_csrf")
    domain?: string;
    httpOnly?: boolean;  // Default: true
    maxAge?: number;
    path?: string;       // Default: "/"
    sameSite?: "lax" | "none" | "strict";  // Default: "lax"
    secure?: boolean;
    signed?: boolean;
  };
  ignoreMethods?: string[];  // Default: ["GET", "HEAD", "OPTIONS"]
  value?: (context: any) => string | undefined;  // Custom token extractor
  saltLength?: number;       // Default: 8
  secretLength?: number;     // Default: 18
  secret?: string;
})
```

## Token Extraction

By default, tokens are extracted from (in order):

1. `body._csrf`
2. `query._csrf`
3. Headers: `csrf-token`, `xsrf-token`, `x-csrf-token`, `x-xsrf-token`

Customize with the `value` option.

## Testing

Run tests to see examples of all features:

```bash
bun test
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
