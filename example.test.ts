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

// Test 2: Token generation
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

// Wait for server to start
await new Promise((resolve) => setTimeout(resolve, 500));

try {
  // Get token and cookie
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

  console.log("\n✅ All tests passed!");
} catch (error) {
  console.log("\n❌ Tests failed:", error);
  process.exit(1);
} finally {
  testApp.stop();
}

process.exit(0);
