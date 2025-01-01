import type { KVNamespace } from "@cloudflare/workers-types";
import type { Context } from "hono";

export type IEnv = {
  Bindings: {
    JWT_SECRET: string;
    VAULT: KVNamespace;
  };
  Variables: {
    session: ISession;
    updateSession: (params: Partial<ISession>) => unknown;
  };
};

export type IContext = Context<IEnv>;

export type ISession = {
  nonce?: string;
  pubkey?: string;
};
