import { Elysia } from "elysia";
import { csrf } from "./src/index";

const app = new Elysia()
  .use(
    csrf({
      cookie: {
        key: "_csrf",
        path: "/",
        httpOnly: true,
        sameSite: "lax",
        secure: false,
      },
    })
  )
  .get("/token", ({ csrfToken }) => {
    return {
      token: csrfToken(),
    };
  })
  .post("/debug", ({ body, query, headers }) => {
    return {
      body,
      query,
      headers: Object.fromEntries(
        Object.entries(headers).filter(
          ([k]) => k.startsWith("x-") || k.startsWith("csrf")
        )
      ),
    };
  })
  .listen(3002);

console.log(`Debug server at localhost:3002`);
