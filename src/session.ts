import { createMiddleware } from "hono/factory";
import { sign, verify } from "hono/jwt";
import type { IEnv, ISession } from "./types";

export const sessions = (params: { ttl: number }) =>
  createMiddleware<IEnv>(async (c, next) => {
    const token = c.req.header("jwt");

    if (token) {
      try {
        const session = await verify(token, c.env.JWT_SECRET);
        c.set("session", session as ISession);
      } catch (e) {
        c.set("session", {});
      }
    } else {
      c.set("session", {});
    }

    c.set("updateSession", (params) => Object.assign(c.var.session, params));

    await next();

    const expiration = ((Date.now() + params.ttl * 1000) / 1000) | 0;

    c.res.headers.set(
      "jwt",
      await sign({ exp: expiration, ...c.var.session }, c.env.JWT_SECRET),
    );
  });
