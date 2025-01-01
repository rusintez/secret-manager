# Secret Manager

Use xsalsa20-poly1305 private key encryption and ed25519 signatures to safely read and write encrypted data on public internet.

### Usage

```bash
$ export SKT_TOKEN=$(skt token) # outputs base58 encoded token
$ skt set GITHUB_TOKEN <some-value-here>
$ skt get GITHUB_TOKEN # outputs "<some-value-here>"
```
