# Secret Manager

Use xsalsa20-poly1305 private key encryption and ed25519 signatures to safely read and write encrypted data on public internet.

### Installation

```bash
$ pnpm install --global @rusintez/skt
```

### Usage

```bash
$ skt token # generates a default token
$ skt set GITHUB_TOKEN <some-value-here>
$ skt get GITHUB_TOKEN # outputs "<some-value-here>"
```

### Namespaces

On your machine

```bash
$ skt token --namespace staging
$ skt set ENV staging --namespace staging
$ skt get ENV # prints 'staging'
$ skt token --export --namespace staging # prints token
```

On another machine

```bash
$ export SKT_TOKEN=<exported-token>
$ skt get ENV # prints 'staging'
```

### Run your own vault

Setup cli and server to run locally

```bash
$ git clone git@github.com:rusintez/secret-manager.git
$ cd secret-manager
$ pnpm install
$ echo "JWT_SECRET=$(openssl rand -hex 32)" > .dev.vars
$ pnpm dev
$ export SKT_DEV=true
$ pnpm link --global
```
