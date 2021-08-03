# Run

Do:

```bash
$ ROCKET_DATABASES='{oracle_signatures={url="./db/signatures.sqlite"}}' cargo run -- --secret="./dev_keys/oracle_secret"
```

or generate a new key by setting `--generate-secret=true`
