#!/usr/bin/env -S npx tsx

import "dotenv/config";

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { program } from "@commander-js/extra-typings";
import bs58 from "bs58";
import { mkdirpSync } from "mkdirp";
import nacl from "tweetnacl";
import {
  concat,
  createBoxKeypair,
  decrypt,
  encode,
  encrypt,
  getBoxKeypair,
  getSignerKeypair,
} from "./helpers";
import { client } from "./index";
import { maskedInput } from "./prompt";

const sktVaultUrl =
  process.env.SKT_VAULT || process.env.SKT_DEV
    ? "http://localhost:8787"
    : "https://skt.runcible.co";

program
  //
  .command("token")
  .option("-n, --namespace <namespace>", "token name", "token")
  .option("-f, --force", "overwrites previous default token (if present)")
  .option("-i, --import", "import another key")
  .action(async (opts) => {
    const path = join(`${process.env.HOME}`, ".config", "skt");
    mkdirpSync(path);

    const keypair = opts.import
      ? getBoxKeypair(await maskedInput("token: "))
      : createBoxKeypair();

    const filepath = join(path, opts.namespace);
    if (existsSync(filepath) && !opts.force)
      throw new Error(`${filepath} already exists, use '--force' to overwrite`);

    writeFileSync(filepath, bs58.encode(keypair.secretKey));
  });

program
  //
  .command("set")
  .argument("<key>")
  .argument("[value]")
  .option("-n, --namespace <namespace>", "token name to use", "token")
  .action(async (key, value, { namespace }) => {
    const home = process.env.HOME as string;
    const filepath = join(home, ".config", "skt", namespace);
    const token = process.env.SKT_TOKEN || readFileSync(filepath, "utf8");
    const { secretKey, publicKey } = getBoxKeypair(token);

    const val = value || (await maskedInput("value: "));
    const keyMessage = bs58.encode(nacl.hash(concat(encode(key), publicKey)));
    const valMessage = encrypt(val, secretKey);

    const keypair = getSignerKeypair(secretKey);
    const pubkey = bs58.encode(keypair.publicKey);

    const { nonce, jwt } = await client(sktVaultUrl)
      [":pubkey"].$get({ param: { pubkey } })
      .then(async (res) => ({
        jwt: res.headers.get("jwt"),
        nonce: await res.json().then(({ nonce }) => nonce),
      }));

    const challenge = bs58.encode(
      nacl.sign(
        concat(bs58.decode(nonce), bs58.decode(keyMessage)),
        keypair.secretKey
      )
    );

    console.log(
      await client(sktVaultUrl, jwt)
        .write.$post({
          json: { key: keyMessage, value: valMessage, challenge },
        })
        .then((res) => res.json())
    );
  });

program
  //
  .command("get")
  .argument("<key>")
  .option("-n, --namespace <namespace>", "token name to use", "token")
  .action(async (key, { namespace }) => {
    const home = process.env.HOME as string;
    const filepath = join(home, ".config", "skt", namespace);
    const token = process.env.SKT_TOKEN || readFileSync(filepath, "utf8");
    const { secretKey, publicKey } = getBoxKeypair(token);

    const keypair = getSignerKeypair(secretKey);
    const pubkey = bs58.encode(keypair.publicKey);

    const { nonce, jwt } = await client(sktVaultUrl)
      [":pubkey"].$get({ param: { pubkey } })
      .then(async (res) => ({
        jwt: res.headers.get("jwt"),
        nonce: await res.json().then(({ nonce }) => nonce),
      }));

    const keyMessage = bs58.encode(nacl.hash(concat(encode(key), publicKey)));

    const challenge = bs58.encode(
      nacl.sign(
        concat(bs58.decode(nonce), bs58.decode(keyMessage)),
        keypair.secretKey
      )
    );

    const res = await client(sktVaultUrl, jwt)
      .read.$post({ json: { key: keyMessage, challenge } })
      .then(
        (res) =>
          res.json() as Promise<{
            key: string;
            value: string;
            message?: string;
          }>
      );

    if (res.message) {
      console.error(res.message);
      return process.exit(1);
    }

    console.log(decrypt(res.value, secretKey));
  });

program.parse(process.argv.slice(0));
