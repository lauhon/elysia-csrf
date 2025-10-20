import { Elysia } from "elysia";
import { csrf } from "../src/index";

/**
 * Advanced CSRF Protection Examples
 */

// Example 1: Custom token extraction from headers
console.log("\n📘 Example 1: Custom header-based token extraction\n");

const app1 = new Elysia()
  .use(
    csrf({
      cookie: true,
      // Extract token from custom header
      value: ({ headers }) => {
        return headers["x-csrf-token"] || headers["x-xsrf-token"];
      },
    })
  )
  .get("/api/token", ({ csrfToken }) => ({
    csrfToken: csrfToken(),
  }))
  .post("/api/data", ({ body }) => ({
    message: "Data received successfully",
    data: body,
  }));

console.log("   Use X-CSRF-Token or X-XSRF-Token header for API requests");

// Example 2: Skip CSRF for specific HTTP methods
console.log("\n📘 Example 2: Custom ignored methods\n");

const app2 = new Elysia()
  .use(
    csrf({
      cookie: true,
      // Allow TRACE and CONNECT in addition to GET, HEAD, OPTIONS
      ignoreMethods: ["GET", "HEAD", "OPTIONS", "TRACE", "CONNECT"],
    })
  )
  .get("/token", ({ csrfToken }) => ({ token: csrfToken() }))
  .post("/submit", ({ body }) => ({ success: true, body }));

console.log("   TRACE and CONNECT methods skip CSRF validation");

// Example 3: Custom cookie configuration for production
console.log("\n📘 Example 3: Production-ready cookie configuration\n");

const app3 = new Elysia()
  .use(
    csrf({
      cookie: {
        key: "XSRF-TOKEN", // Custom cookie name
        path: "/",
        httpOnly: true, // Prevent JavaScript access
        secure: true, // HTTPS only
        sameSite: "strict", // Strict same-site policy
        maxAge: 3600, // 1 hour
        domain: "example.com", // Specific domain
      },
      saltLength: 16, // Longer salt for extra security
      secretLength: 32, // Longer secret
    })
  )
  .get("/token", ({ csrfToken }) => ({ token: csrfToken() }));

console.log("   Secure configuration for production with HTTPS");

// Example 4: Custom error handling
console.log("\n📘 Example 4: Custom error handling\n");

const app4 = new Elysia()
  .use(
    csrf({
      cookie: true,
    })
  )
  .onError(({ error, set, request }) => {
    // Custom error response for CSRF failures
    if ("message" in error && error.message === "Invalid CSRF token") {
      set.status = 403;
      return {
        error: "CSRF_VALIDATION_FAILED",
        message:
          "The CSRF token is missing or invalid. Please refresh and try again.",
        timestamp: new Date().toISOString(),
        path: new URL(request.url).pathname,
      };
    }
    return error;
  })
  .get("/token", ({ csrfToken }) => ({ token: csrfToken() }))
  .post("/submit", ({ body }) => ({ success: true }));

console.log("   Returns structured JSON error for CSRF failures");

// Example 5: Multiple token extraction sources
console.log("\n📘 Example 5: Multiple token sources with priority\n");

const app5 = new Elysia()
  .use(
    csrf({
      cookie: true,
      value: ({ body, query, headers }) => {
        // Priority: body > query > headers
        return (
          body?._csrf ||
          body?.csrf ||
          query?._csrf ||
          query?.csrf ||
          headers["x-csrf-token"] ||
          headers["csrf-token"] ||
          headers["x-xsrf-token"]
        );
      },
    })
  )
  .get("/token", ({ csrfToken }) => ({ token: csrfToken() }))
  .post("/submit", ({ body }) => ({ success: true }));

console.log("   Accepts token from body (_csrf or csrf), query, or headers");

// Example 6: Integration with authentication
console.log("\n📘 Example 6: CSRF with authentication\n");

const app6 = new Elysia()
  // Authentication plugin (simplified example)
  .derive(({ headers }) => ({
    user: headers.authorization ? { id: 1, name: "User" } : null,
  }))
  // CSRF protection
  .use(
    csrf({
      cookie: true,
    })
  )
  // Public endpoint (no auth, no CSRF needed)
  .get("/", () => ({ message: "Public page" }))
  // Get token (no auth needed)
  .get("/token", ({ csrfToken }) => ({ token: csrfToken() }))
  // Protected endpoint (requires auth and CSRF)
  .post("/api/user/profile", ({ user, body }) => {
    if (!user) {
      return new Response("Unauthorized", { status: 401 });
    }
    return {
      message: "Profile updated",
      user,
      data: body,
    };
  });

console.log("   Combines CSRF protection with authentication");

// Example 7: SPA (Single Page Application) pattern
console.log("\n📘 Example 7: SPA with CSRF protection\n");

const app7 = new Elysia()
  .use(
    csrf({
      cookie: {
        key: "_csrf",
        httpOnly: true,
        sameSite: "lax",
      },
      // Accept token from header for JSON APIs
      value: ({ body, headers }) => {
        return headers["x-csrf-token"] || body?._csrf;
      },
    })
  )
  // Serve SPA
  .get("/", () => ({
    html: `
      <!DOCTYPE html>
      <html>
        <head><title>SPA Example</title></head>
        <body>
          <div id="app"></div>
          <script>
            // Get CSRF token on app initialization
            let csrfToken = null;
            
            fetch('/api/csrf-token')
              .then(r => r.json())
              .then(data => {
                csrfToken = data.token;
                console.log('CSRF token loaded');
              });
            
            // Helper function for API calls
            async function apiPost(url, data) {
              const response = await fetch(url, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify(data)
              });
              return response.json();
            }
            
            // Example usage
            // apiPost('/api/data', { key: 'value' });
          </script>
        </body>
      </html>
    `,
  }))
  // API endpoint to get token
  .get("/api/csrf-token", ({ csrfToken }) => ({
    token: csrfToken(),
  }))
  // API endpoint with CSRF protection
  .post("/api/data", ({ body }) => ({
    success: true,
    received: body,
  }));

console.log("   SPA pattern with token in header");

console.log("\n✅ All examples defined successfully!");
console.log("   These patterns show various ways to use the CSRF plugin.\n");

export { app1, app2, app3, app4, app5, app6, app7 };
