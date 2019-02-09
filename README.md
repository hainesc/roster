# Roster - An OpenID Connect provider

## Caution

It is a prototype only. Never use it at prod.

## Usage

```shell
echo "127.0.0.1	accounts.example.com" >> /etc/hosts
echo "issuer: http://accounts.example.com" > /tmp/config.yaml
./roster serve  # Add sudo if neccessary
```

Open your browser, signup at http://accounts.example.com/signup and register a client at http://accounts.example.com/client

Run cmd/example-app
Run gini/dexter
