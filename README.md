# Secret Manager

Use xsalsa20-poly1305 private key encryption and ed25519 signatures to safely read and write encrypted data on public internet.

### Usage

```bash
$ export SKT_TOKEN=$(skt token) # outputs base58 encoded token
$ skt set GITHUB_TOKEN <some-value-here>
$ skt get GITHUB_TOKEN # outputs "<some-value-here>"
```

### Run your own vault

Setup cli and server to run locally

```bash
$ git clone git@github.com:rusintez/secret-manager.git
$ cd secret-manager
$ pnpm install
$ pnpm dev
$ export SKT_DEV=true
$ pnpm link --global
```
