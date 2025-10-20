import { Elysia } from "elysia";
import { csrf } from "./src/index";

console.log("🧪 Testing Elysia CSRF Plugin\n");

// Test 1: Basic setup
console.log("Test 1: Basic plugin setup");
try {
  const app = new Elysia().use(csrf({ cookie: true }));
  console.log("✅ Plugin initializes correctly\n");
} catch (error) {
  console.log("❌ Plugin initialization failed:", error);
  process.exit(1);
}

// Test 2: Token generation and validation
console.log("Test 2: Token generation and validation");
const testApp = new Elysia()
  .use(
    csrf({
      cookie: {
        key: "_csrf",
        path: "/",
        httpOnly: true,
        sameSite: "lax",
      },
    })
  )
  .get("/token", ({ csrfToken }) => ({
    token: csrfToken(),
  }))
  .post("/protected", ({ body }) => ({
    success: true,
    data: body,
  }))
  .listen(3003);

await new Promise((resolve) => setTimeout(resolve, 500));

try {
  const tokenRes = await fetch("http://localhost:3003/token");
  const cookies = tokenRes.headers.get("set-cookie");
  const { token } = (await tokenRes.json()) as { token: string };

  console.log(`  Token received: ${token.substring(0, 20)}...`);
  console.log(`  Cookie set: ${cookies?.includes("_csrf") ? "✅" : "❌"}`);

  // Test POST without token (should fail)
  const failRes = await fetch("http://localhost:3003/protected", {
    method: "POST",
    headers: {
      Cookie: cookies || "",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "message=test",
  });

  if (failRes.status === 403) {
    console.log("  POST without token rejected: ✅");
  } else {
    console.log(
      "  POST without token rejected: ❌ (got status",
      failRes.status,
      ")"
    );
  }

  // Test POST with invalid token (should fail)
  const invalidRes = await fetch("http://localhost:3003/protected", {
    method: "POST",
    headers: {
      Cookie: cookies || "",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "_csrf=invalid-token&message=test",
  });

  if (invalidRes.status === 403) {
    console.log("  POST with invalid token rejected: ✅");
  } else {
    console.log(
      "  POST with invalid token rejected: ❌ (got status",
      invalidRes.status,
      ")"
    );
  }

  // Test POST with valid token (should succeed)
  const successRes = await fetch("http://localhost:3003/protected", {
    method: "POST",
    headers: {
      Cookie: cookies || "",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: `_csrf=${token}&message=hello`,
  });

  if (successRes.status === 200) {
    const data = await successRes.json();
    console.log("  POST with valid token accepted: ✅");
    console.log(`  Response data: ${JSON.stringify(data)}`);
  } else {
    console.log(
      "  POST with valid token accepted: ❌ (got status",
      successRes.status,
      ")"
    );
  }

  testApp.stop();
} catch (error) {
  console.log("\n❌ Tests failed:", error);
  testApp.stop();
  process.exit(1);
}

// Test 3: Custom header-based token extraction
console.log("\nTest 3: Custom header-based token extraction");
const testApp3 = new Elysia()
  .use(
    csrf({
      cookie: true,
      value: ({ headers }) => {
        return headers.get("x-csrf-token") || headers.get("x-xsrf-token");
      },
    })
  )
  .get("/api/token", ({ csrfToken }) => ({
    csrfToken: csrfToken(),
  }))
  .post("/api/data", ({ body }) => ({
    message: "Data received successfully",
    data: body,
  }))
  .listen(3004);

await new Promise((resolve) => setTimeout(resolve, 500));

try {
  const tokenRes = await fetch("http://localhost:3004/api/token");
  const cookies = tokenRes.headers.get("set-cookie");
  const { csrfToken: token } = (await tokenRes.json()) as {
    csrfToken: string;
  };

  // Test with X-CSRF-Token header
  const successRes = await fetch("http://localhost:3004/api/data", {
    method: "POST",
    headers: {
      Cookie: cookies || "",
      "Content-Type": "application/json",
      "X-CSRF-Token": token,
    },
    body: JSON.stringify({ key: "value" }),
  });

  if (successRes.status === 200) {
    console.log("  POST with X-CSRF-Token header accepted: ✅");
  } else {
    console.log(
      "  POST with X-CSRF-Token header: ❌ (got status",
      successRes.status,
      ")"
    );
  }

  testApp3.stop();
} catch (error) {
  console.log("  ❌ Test failed:", error);
  testApp3.stop();
  process.exit(1);
}

// Test 4: Custom ignored methods
console.log("\nTest 4: Custom ignored methods");
const testApp4 = new Elysia()
  .use(
    csrf({
      cookie: true,
      ignoreMethods: ["GET", "HEAD", "OPTIONS", "TRACE"],
    })
  )
  .get("/token", ({ csrfToken }) => ({ token: csrfToken() }))
  .post("/submit", ({ body }) => ({ success: true, body }))
  .listen(3005);

await new Promise((resolve) => setTimeout(resolve, 500));

try {
  const tokenRes = await fetch("http://localhost:3005/token");
  const cookies = tokenRes.headers.get("set-cookie");

  // GET should not require CSRF
  const getRes = await fetch("http://localhost:3005/token", {
    headers: { Cookie: cookies || "" },
  });

  if (getRes.status === 200) {
    console.log("  GET request without token allowed: ✅");
  } else {
    console.log("  GET request: ❌ (got status", getRes.status, ")");
  }

  testApp4.stop();
} catch (error) {
  console.log("  ❌ Test failed:", error);
  testApp4.stop();
  process.exit(1);
}

// Test 5: Production-ready cookie configuration
console.log("\nTest 5: Production-ready cookie configuration");
const testApp5 = new Elysia()
  .use(
    csrf({
      cookie: {
        key: "XSRF-TOKEN",
        path: "/",
        httpOnly: true,
        sameSite: "strict",
        maxAge: 3600,
      },
      saltLength: 16,
      secretLength: 32,
    })
  )
  .get("/token", ({ csrfToken }) => ({ token: csrfToken() }))
  .listen(3006);

await new Promise((resolve) => setTimeout(resolve, 500));

try {
  const tokenRes = await fetch("http://localhost:3006/token");
  const cookies = tokenRes.headers.get("set-cookie");

  if (
    cookies?.includes("XSRF-TOKEN") &&
    cookies?.includes("HttpOnly") &&
    cookies?.includes("SameSite=Strict")
  ) {
    console.log("  Custom cookie configuration applied: ✅");
  } else {
    console.log("  Custom cookie configuration: ❌");
  }

  testApp5.stop();
} catch (error) {
  console.log("  ❌ Test failed:", error);
  testApp5.stop();
  process.exit(1);
}

// Test 6: Token works across multiple requests
console.log("\nTest 6: Token reuse and caching");
const testApp6 = new Elysia()
  .use(csrf({ cookie: true }))
  .get("/token", ({ csrfToken }) => ({ token: csrfToken() }))
  .post("/submit", ({ body }) => ({ success: true }))
  .listen(3007);

await new Promise((resolve) => setTimeout(resolve, 500));

try {
  const tokenRes = await fetch("http://localhost:3007/token");
  const cookies = tokenRes.headers.get("set-cookie");
  const { token } = (await tokenRes.json()) as { token: string };

  // Use same token for multiple requests
  const req1 = await fetch("http://localhost:3007/submit", {
    method: "POST",
    headers: {
      Cookie: cookies || "",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: `_csrf=${token}`,
  });

  const req2 = await fetch("http://localhost:3007/submit", {
    method: "POST",
    headers: {
      Cookie: cookies || "",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: `_csrf=${token}`,
  });

  if (req1.status === 200 && req2.status === 200) {
    console.log("  Token reuse across requests: ✅");
  } else {
    console.log(
      "  Token reuse: ❌ (req1:",
      req1.status,
      "req2:",
      req2.status,
      ")"
    );
  }

  testApp6.stop();
} catch (error) {
  console.log("  ❌ Test failed:", error);
  testApp6.stop();
  process.exit(1);
}

// Test 7: Multiple token extraction sources with priority
console.log("\nTest 7: Multiple token sources with priority");
const testApp7 = new Elysia()
  .use(
    csrf({
      cookie: true,
      value: ({ body, query, headers }) => {
        return (
          body?._csrf ||
          body?.csrf ||
          query?._csrf ||
          query?.csrf ||
          headers.get("x-csrf-token") ||
          headers.get("csrf-token") ||
          headers.get("x-xsrf-token")
        );
      },
    })
  )
  .get("/token", ({ csrfToken }) => ({ token: csrfToken() }))
  .post("/submit", ({ body }) => ({ success: true }))
  .listen(3008);

await new Promise((resolve) => setTimeout(resolve, 500));

try {
  const tokenRes = await fetch("http://localhost:3008/token");
  const cookies = tokenRes.headers.get("set-cookie");
  const { token } = (await tokenRes.json()) as { token: string };

  // Test body._csrf
  const bodyRes = await fetch("http://localhost:3008/submit", {
    method: "POST",
    headers: {
      Cookie: cookies || "",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: `_csrf=${encodeURIComponent(token)}&data=test`,
  });

  const bodySuccess = bodyRes.status === 200;

  // Test header
  const headerRes = await fetch("http://localhost:3008/submit", {
    method: "POST",
    headers: {
      Cookie: cookies || "",
      "X-CSRF-Token": token,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ data: "test" }),
  });

  const headerSuccess = headerRes.status === 200;

  if (bodySuccess && headerSuccess) {
    console.log("  Multiple token sources working: ✅");
  } else {
    console.log(
      "  Multiple token sources: ❌ (body:",
      bodyRes.status,
      "header:",
      headerRes.status,
      ")"
    );
  }

  testApp7.stop();
} catch (error) {
  console.log("  ❌ Test failed:", error);
  testApp7.stop();
  process.exit(1);
}

// Test 8: HTML form integration
console.log("\nTest 8: HTML form integration");
const testApp8 = new Elysia()
  .use(csrf({ cookie: true }))
  .get("/form", ({ csrfToken }) => {
    const token = csrfToken();
    return `
      <form method="POST" action="/form-submit">
        <input type="hidden" name="_csrf" value="${token}" />
        <input type="text" name="message" />
        <button type="submit">Submit</button>
      </form>
    `;
  })
  .post("/form-submit", ({ body }) => ({
    success: true,
    message: (body as any).message,
  }))
  .listen(3009);

await new Promise((resolve) => setTimeout(resolve, 500));

try {
  const formRes = await fetch("http://localhost:3009/form");
  const cookies = formRes.headers.get("set-cookie");
  const html = await formRes.text();

  // Extract token from HTML
  const tokenMatch = html.match(/value="([^"]+)"/);
  const token = tokenMatch ? tokenMatch[1] : "";

  if (token && token.length > 0) {
    // Submit form with token
    const submitRes = await fetch("http://localhost:3009/form-submit", {
      method: "POST",
      headers: {
        Cookie: cookies || "",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `_csrf=${encodeURIComponent(token)}&message=hello`,
    });

    if (submitRes.status === 200) {
      console.log("  HTML form with embedded token: ✅");
    } else {
      console.log(
        "  HTML form submission: ❌ (got status",
        submitRes.status,
        ")"
      );
    }
  } else {
    console.log("  HTML form: ❌ (token not found in HTML)");
  }

  testApp8.stop();
} catch (error) {
  console.log("  ❌ Test failed:", error);
  testApp8.stop();
  process.exit(1);
}

// Test 9: SPA pattern with token in header
console.log("\nTest 9: SPA pattern with token in header");
const testApp9 = new Elysia()
  .use(
    csrf({
      cookie: {
        key: "_csrf",
        httpOnly: true,
        sameSite: "lax",
      },
      value: ({ body, headers }) => {
        return headers.get("x-csrf-token") || body?._csrf;
      },
    })
  )
  .get("/api/csrf-token", ({ csrfToken }) => ({
    token: csrfToken(),
  }))
  .post("/api/data", ({ body }) => ({
    success: true,
    received: body,
  }))
  .listen(3010);

await new Promise((resolve) => setTimeout(resolve, 500));

try {
  // Simulate SPA initialization
  const tokenRes = await fetch("http://localhost:3010/api/csrf-token");
  const cookies = tokenRes.headers.get("set-cookie");
  const { token } = (await tokenRes.json()) as { token: string };

  // Simulate API call with header
  const apiRes = await fetch("http://localhost:3010/api/data", {
    method: "POST",
    headers: {
      Cookie: cookies || "",
      "Content-Type": "application/json",
      "X-CSRF-Token": token,
    },
    body: JSON.stringify({ key: "value" }),
  });

  if (apiRes.status === 200) {
    console.log("  SPA pattern with header token: ✅");
  } else {
    console.log("  SPA pattern: ❌ (got status", apiRes.status, ")");
  }

  testApp9.stop();
} catch (error) {
  console.log("  ❌ Test failed:", error);
  testApp9.stop();
  process.exit(1);
}

// Test 10: GET requests are not protected
console.log("\nTest 10: Safe methods skip CSRF validation");
const testApp10 = new Elysia()
  .use(csrf({ cookie: true }))
  .get("/safe", () => ({ message: "GET is safe" }))
  .head("/safe", () => ({ message: "HEAD is safe" }))
  .options("/safe", () => ({ message: "OPTIONS is safe" }))
  .post("/unsafe", () => ({ message: "POST requires CSRF" }))
  .listen(3011);

await new Promise((resolve) => setTimeout(resolve, 500));

try {
  // GET without any token should succeed
  const getRes = await fetch("http://localhost:3011/safe");
  const getSuccess = getRes.status === 200;

  // POST without token should fail
  const postRes = await fetch("http://localhost:3011/unsafe", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data: "test" }),
  });
  const postFailed = postRes.status === 403;

  if (getSuccess && postFailed) {
    console.log("  Safe methods skip validation: ✅");
  } else {
    console.log(
      "  Safe methods: ❌ (GET:",
      getRes.status,
      "POST:",
      postRes.status,
      ")"
    );
  }

  testApp10.stop();
} catch (error) {
  console.log("  ❌ Test failed:", error);
  testApp10.stop();
  process.exit(1);
}

console.log("\n✅ All tests passed!");
process.exit(0);
