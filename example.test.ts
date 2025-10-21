import { describe, expect, test } from "bun:test";
import { Elysia } from "elysia";
import { csrf } from "./src/index";

describe("Elysia CSRF Plugin", () => {
  test.only("should initialize plugin correctly", () => {
    expect(() => {
      new Elysia().use(csrf({ cookie: true }));
    }).not.toThrow();
  });

  test.only("should generate token and set cookie", async () => {
    const app = new Elysia()
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
      .get("/token", ({ csrfToken }) => ({ token: csrfToken() }));

    const tokenRes = await app.handle(new Request("http://localhost/token"));
    const cookies = tokenRes.headers.get("set-cookie");
    const { token } = (await tokenRes.json()) as { token: string };

    expect(token).toBeDefined();
    expect(token.length).toBeGreaterThan(0);
    expect(cookies).toContain("_csrf");
  });

  test.only("should reject POST without token", async () => {
    const app = new Elysia()
      .use(csrf({ cookie: true }))
      .get("/token", ({ csrfToken }) => ({ token: csrfToken() }))
      .post("/protected", ({ body }) => ({ success: true, data: body }));

    const tokenRes = await app.handle(new Request("http://localhost/token"));
    const cookies = tokenRes.headers.get("set-cookie");

    const failRes = await app.handle(
      new Request("http://localhost/protected", {
        method: "POST",
        headers: {
          Cookie: cookies || "",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "message=test",
      })
    );

    expect(failRes.status).toBe(403);
  });

  test.only("should reject POST with invalid token", async () => {
    const app = new Elysia()
      .use(csrf({ cookie: true }))
      .get("/token", ({ csrfToken }) => ({ token: csrfToken() }))
      .post("/protected", ({ body }) => ({ success: true, data: body }));

    const tokenRes = await app.handle(new Request("http://localhost/token"));
    const cookies = tokenRes.headers.get("set-cookie");

    const invalidRes = await app.handle(
      new Request("http://localhost/protected", {
        method: "POST",
        headers: {
          Cookie: cookies || "",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "_csrf=invalid-token&message=test",
      })
    );

    expect(invalidRes.status).toBe(403);
  });

  test("should accept POST with valid token", async () => {
    const app = new Elysia()
      .use(csrf({ cookie: true }))
      .get("/token", ({ csrfToken }) => ({ token: csrfToken() }))
      .post("/protected", ({ body }) => ({ success: true, data: body }));

    const tokenRes = await app.handle(new Request("http://localhost/token"));
    const cookies = tokenRes.headers.get("set-cookie");
    const { token } = (await tokenRes.json()) as { token: string };

    const successRes = await app.handle(
      new Request("http://localhost/protected", {
        method: "POST",
        headers: {
          Cookie: cookies || "",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `_csrf=${token}&message=hello`,
      })
    );

    expect(successRes.status).toBe(200);
    const data = await successRes.json();
    expect(data).toHaveProperty("success", true);
  });

  test("should extract token from custom header", async () => {
    const app = new Elysia()
      .use(
        csrf({
          cookie: true,
          value: ({ headers }) => {
            return headers.get("x-csrf-token") || headers.get("x-xsrf-token");
          },
        })
      )
      .get("/api/token", ({ csrfToken }) => ({ csrfToken: csrfToken() }))
      .post("/api/data", ({ body }) => ({
        message: "Data received successfully",
        data: body,
      }));

    const tokenRes = await app.handle(
      new Request("http://localhost/api/token")
    );
    const cookies = tokenRes.headers.get("set-cookie");
    const { csrfToken: token } = (await tokenRes.json()) as {
      csrfToken: string;
    };

    const successRes = await app.handle(
      new Request("http://localhost/api/data", {
        method: "POST",
        headers: {
          Cookie: cookies || "",
          "Content-Type": "application/json",
          "X-CSRF-Token": token,
        },
        body: JSON.stringify({ key: "value" }),
      })
    );

    expect(successRes.status).toBe(200);
  });

  test("should allow custom ignored methods", async () => {
    const app = new Elysia()
      .use(
        csrf({
          cookie: true,
          ignoreMethods: ["GET", "HEAD", "OPTIONS", "TRACE"],
        })
      )
      .get("/token", ({ csrfToken }) => ({ token: csrfToken() }))
      .post("/submit", ({ body }) => ({ success: true, body }));

    const tokenRes = await app.handle(new Request("http://localhost/token"));
    const cookies = tokenRes.headers.get("set-cookie");

    const getRes = await app.handle(
      new Request("http://localhost/token", {
        headers: { Cookie: cookies || "" },
      })
    );

    expect(getRes.status).toBe(200);
  });

  test("should apply custom cookie configuration", async () => {
    const app = new Elysia()
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
      .get("/token", ({ csrfToken }) => ({ token: csrfToken() }));

    const tokenRes = await app.handle(new Request("http://localhost/token"));
    const cookies = tokenRes.headers.get("set-cookie");

    expect(cookies).toContain("XSRF-TOKEN");
    expect(cookies).toContain("HttpOnly");
    expect(cookies).toContain("SameSite=Strict");
  });

  test("should allow token reuse across requests", async () => {
    const app = new Elysia()
      .use(csrf({ cookie: true }))
      .get("/token", ({ csrfToken }) => ({ token: csrfToken() }))
      .post("/submit", ({ body }) => ({ success: true }));

    const tokenRes = await app.handle(new Request("http://localhost/token"));
    const cookies = tokenRes.headers.get("set-cookie");
    const { token } = (await tokenRes.json()) as { token: string };

    const req1 = await app.handle(
      new Request("http://localhost/submit", {
        method: "POST",
        headers: {
          Cookie: cookies || "",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `_csrf=${token}`,
      })
    );

    const req2 = await app.handle(
      new Request("http://localhost/submit", {
        method: "POST",
        headers: {
          Cookie: cookies || "",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `_csrf=${token}`,
      })
    );

    expect(req1.status).toBe(200);
    expect(req2.status).toBe(200);
  });

  test("should support multiple token sources", async () => {
    const app = new Elysia()
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
      .post("/submit", ({ body }) => ({ success: true }));

    const tokenRes = await app.handle(new Request("http://localhost/token"));
    const cookies = tokenRes.headers.get("set-cookie");
    const { token } = (await tokenRes.json()) as { token: string };

    const bodyRes = await app.handle(
      new Request("http://localhost/submit", {
        method: "POST",
        headers: {
          Cookie: cookies || "",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `_csrf=${encodeURIComponent(token)}&data=test`,
      })
    );

    const headerRes = await app.handle(
      new Request("http://localhost/submit", {
        method: "POST",
        headers: {
          Cookie: cookies || "",
          "X-CSRF-Token": token,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ data: "test" }),
      })
    );

    expect(bodyRes.status).toBe(200);
    expect(headerRes.status).toBe(200);
  });

  test("should work with HTML forms", async () => {
    const app = new Elysia()
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
      }));

    const formRes = await app.handle(new Request("http://localhost/form"));
    const cookies = formRes.headers.get("set-cookie");
    const html = await formRes.text();

    const tokenMatch = html.match(/value="([^"]+)"/);
    const token = (tokenMatch ? tokenMatch[1] : "") ?? "";

    expect(token.length).toBeGreaterThan(0);

    const submitRes = await app.handle(
      new Request("http://localhost/form-submit", {
        method: "POST",
        headers: {
          Cookie: cookies || "",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `_csrf=${encodeURIComponent(token)}&message=hello`,
      })
    );

    expect(submitRes.status).toBe(200);
  });

  test("should support SPA pattern", async () => {
    const app = new Elysia()
      .use(
        csrf({
          cookie: {
            key: "_csrf",
            httpOnly: true,
            sameSite: "lax",
          },
          value: ({ body, headers }) => {
            return (
              (typeof headers.get === "function"
                ? headers.get("x-csrf-token")
                : headers["x-csrf-token"]) || body?._csrf
            );
          },
        })
      )
      .get("/api/csrf-token", ({ csrfToken }) => ({ token: csrfToken() }))
      .post("/api/data", ({ body }) => ({ success: true, received: body }));

    const tokenRes = await app.handle(
      new Request("http://localhost/api/csrf-token")
    );
    const cookies = tokenRes.headers.get("set-cookie");
    const { token } = (await tokenRes.json()) as { token: string };

    const apiRes = await app.handle(
      new Request("http://localhost/api/data", {
        method: "POST",
        headers: {
          Cookie: cookies || "",
          "Content-Type": "application/json",
          "X-CSRF-Token": token,
        },
        body: JSON.stringify({ key: "value" }),
      })
    );

    expect(apiRes.status).toBe(200);
  });

  test.only("should skip validation for safe methods", async () => {
    const app = new Elysia()
      .use(csrf({ cookie: true }))
      .get("/safe", () => ({ message: "GET is safe" }))
      .head("/safe", () => ({ message: "HEAD is safe" }))
      .options("/safe", () => ({ message: "OPTIONS is safe" }))
      .post("/unsafe", () => ({ message: "POST requires CSRF" }));

    const getRes = await app.handle(new Request("http://localhost/safe"));
    expect(getRes.status).toBe(200);

    const postRes = await app.handle(
      new Request("http://localhost/unsafe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ data: "test" }),
      })
    );
    expect(postRes.status).toBe(403);
  });
});
