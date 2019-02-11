# Roster - An OpenID Connect provider

## Caution

It is a prototype only. Never use it at prod.

Only [Code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)(Click this hyperlink to see detail) is implemented recently. Error handle is not enough and the behavior of other flow may undefined.

## Usage

```shell
echo "127.0.0.1	accounts.example.com" >> /etc/hosts
echo "issuer: http://accounts.example.com" > /tmp/config.yaml
./roster serve  # Add sudo if neccessary
```

Open your browser, signup at http://accounts.example.com/signup and register a client at http://accounts.example.com/client

Run cmd/example-app

Run cmd/kube-auth
