# Cloudflare Tunnel deployment

The production route reuses the host's existing Docker connector:

- container: `malware-package-browser-cloudflared`
- image: `cloudflare/cloudflared:latest`
- network mode: `host`
- public hostname: `alert.dataisland.org`
- origin: `http://127.0.0.1:8787`

The route is configured remotely in Cloudflare. This project does not contain,
write, or install a Tunnel token. Cloudflare Access protects the hostname with
the reusable `OwnCode` allow policy for `dataisland98@gmail.com`, using only the
configured Google identity provider.
