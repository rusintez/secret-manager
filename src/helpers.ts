import bs58 from "bs58";
import nacl from "tweetnacl";

export const encode = (...strs: string[]) =>
  concat(...strs.map((str) => new TextEncoder().encode(str)));

export const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

export const verifySignature = (
  pubkey: Uint8Array,
  message: Uint8Array,
  nonce: Uint8Array
) => {
  const data = nacl.sign.open(message, pubkey);
  if (!data) throw new Error("invalid signer");
  if (data.length === nonce.length && data.every((b, i) => nonce.at(i) === b))
    return;
  throw new Error("invalid signature");
};

export const createNonce = () =>
  crypto.getRandomValues(new Uint8Array(nacl.secretbox.nonceLength));

export const concat = (...buffers: Uint8Array[]) => {
  const space = buffers
    .map(({ byteLength }) => byteLength)
    .reduce((m, a) => m + a, 0);

  let offset = 0;
  const output = new Uint8Array(space);

  for (const buffer of buffers) {
    output.set(buffer, offset);
    offset += buffer.byteLength;
  }

  return output;
};

export const split = (buffer: Uint8Array, offset: number) => [
  buffer.slice(0, offset),
  buffer.slice(offset),
];

export const createBoxKeypair = () => nacl.box.keyPair();

export const getBoxKeypair = (token: string) =>
  nacl.box.keyPair.fromSecretKey(bs58.decode(token));

export const getSignerKeypair = (secret: Uint8Array) =>
  nacl.sign.keyPair.fromSeed(secret);

import readline from "node:readline/promises";

export const input = (prompt: string) =>
  readline
    .createInterface({ input: process.stdin, output: process.stdout })
    .question(prompt);

export const encrypt = (str: string, secret: Uint8Array) => {
  const nonce = createNonce();
  const message = concat(nonce, nacl.secretbox(encode(str), nonce, secret));
  return bs58.encode(message);
};

export const decrypt = (str: string, secret: Uint8Array) => {
  const [nonce, box] = split(bs58.decode(str), nacl.secretbox.nonceLength);
  const result = nacl.secretbox.open(box, nonce, secret);
  if (!result) throw new Error("invalid message");
  return decode(result);
};
