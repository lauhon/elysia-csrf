import { Elysia } from "elysia";
import { csrf } from "../src/index";

const app = new Elysia()
  // Add CSRF protection with cookie-based storage
  .use(
    csrf({
      cookie: {
        key: "_csrf",
        path: "/",
        httpOnly: true,
        sameSite: "lax",
        secure: false, // Set to true in production with HTTPS
      },
    })
  )
  // GET endpoint - CSRF validation is skipped
  .get("/", () => {
    return `
      <!DOCTYPE html>
      <html>
        <head><title>CSRF Example</title></head>
        <body>
          <h1>CSRF Protection Demo</h1>
          <form action="/submit" method="POST">
            <input type="text" name="message" placeholder="Enter a message" required />
            <button type="submit">Submit (No CSRF Token - Will Fail)</button>
          </form>
          <br />
          <form action="/protected" method="POST" id="protectedForm">
            <input type="text" name="message" placeholder="Enter a message" required />
            <input type="hidden" name="_csrf" id="csrfToken" />
            <button type="submit">Submit (With CSRF Token - Will Succeed)</button>
          </form>
          <script>
            // Get CSRF token from API and populate form
            fetch('/token')
              .then(res => res.json())
              .then(data => {
                document.getElementById('csrfToken').value = data.token;
              });
          </script>
        </body>
      </html>
    `;
  })
  // Endpoint to get CSRF token
  .get("/token", ({ csrfToken }) => {
    return {
      token: csrfToken(),
    };
  })
  // POST endpoint without CSRF token - will fail validation
  .post("/submit", () => {
    return { success: true, message: "This should not be reached" };
  })
  // POST endpoint with CSRF token - will succeed
  .post("/protected", ({ body }) => {
    return {
      success: true,
      message: `Received: ${(body as any).message}`,
    };
  })
  .listen(3001);

console.log(
  `🦊 Elysia CSRF example is running at ${app.server?.hostname}:${app.server?.port}`
);
