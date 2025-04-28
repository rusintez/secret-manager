import { zValidator } from "@hono/zod-validator";
import bs58 from "bs58";
import { Hono } from "hono";
import { hc } from "hono/client";
import * as v from "zod";
import { concat, createNonce, encode, verifySignature } from "./helpers";
import { sessions } from "./session";
import type { IEnv } from "./types";

const app = new Hono<IEnv>()
  .use("/*", sessions({ ttl: 60 }))

  .get("/:pubkey", (c) => {
    const nonce = bs58.encode(createNonce());
    const pubkey = c.req.param("pubkey");
    c.var.updateSession({ nonce, pubkey });
    return c.json({ nonce });
  })

  .post(
    "/write",
    zValidator(
      "json",
      // base58 encoded secretbox(key), sign(secretbox(value), pubkey), sign(concat(nonce, key))
      v.object({ key: v.string(), value: v.string(), challenge: v.string() })
    ),
    async (c) => {
      const { key, value, challenge } = c.req.valid("json");
      const { nonce, pubkey } = c.var.session;
      if (!pubkey || !nonce) throw new Error("missing handshake");
      c.var.updateSession({ nonce: undefined, pubkey: undefined });

      const payload = concat(bs58.decode(nonce), bs58.decode(key));
      verifySignature(bs58.decode(pubkey), bs58.decode(challenge), payload);

      await c.env.VAULT.put(`${pubkey}/${key}`, JSON.stringify({ key, value }));

      return c.json({ ok: true });
    }
  )

  .post(
    "/read",
    // base58 encoded secretbox(key), sign(concat(nonce, key))
    zValidator("json", v.object({ key: v.string(), challenge: v.string() })),
    async (c) => {
      const { challenge, key } = c.req.valid("json");
      const { nonce, pubkey } = c.var.session;
      if (!pubkey || !nonce) throw new Error("missing handshake");
      c.var.updateSession({ nonce: undefined, pubkey: undefined });

      const payload = concat(bs58.decode(nonce), bs58.decode(key));
      verifySignature(bs58.decode(pubkey), bs58.decode(challenge), payload);

      const result = await c.env.VAULT.get(`${pubkey}/${key}`);
      if (!result) return c.json({ message: "not found" }, 404);
      return c.json(JSON.parse(result)); // { key, value }
    }
  );

// .post(
//   "/list",
//   zValidator("query", v.object({ cursor: v.optional(v.string()) })),
//   // base58 encoded sign(concat(nonce, "keys"))
//   zValidator("json", v.object({ challenge: v.string() })),
//   async (c) => {
//     const { challenge } = c.req.valid("json");
//     const { nonce, pubkey } = c.var.session;
//     if (!pubkey || !nonce) throw new Error("missing handshake");
//     c.var.updateSession({ nonce: undefined, pubkey: undefined });

//     let { cursor } = c.req.valid("query");
//     const payload = concat(
//       bs58.decode(nonce),
//       encode("keys", cursor as string)
//     );
//     verifySignature(bs58.decode(pubkey), bs58.decode(challenge), payload);

//     const result = await c.env.VAULT.list({ prefix: `${pubkey}/`, cursor });
//     cursor = "cursor" in result ? result.cursor : undefined;
//     const keys = result.keys.map(({ name }) => name.split(`${pubkey}/`)[1]);
//     return c.json({ keys, ...(cursor && { cursor }) });
//   }
// );

export default app;

export const client = (baseUrl: string, jwt?: string | null) =>
  hc<typeof app>(baseUrl, {
    init: {
      headers: { ...(jwt && { jwt }), "content-type": "application/json" },
    },
  });
