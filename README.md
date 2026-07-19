# lucky6

`lucky6` is a small Cloudflare Worker that lets IPv6-only clients reach public HTTP(S) upstreams through Cloudflare.

Encode the upstream scheme and authority as the first two path components:

```text
https://lucky6.xhjkl.xyz/<http-or-https>/<host>/<path>?<query>
```

For example:

```sh
curl 'https://lucky6.xhjkl.xyz/https/api.jup.ag/swap/v2'
```

The Worker forwards the request method, headers, body, path, and query, and returns the upstream response without buffering it. Redirects are returned to the caller rather than followed. Private, local, reserved, and self-referential targets are rejected; WebSocket upgrades are not supported.

```sh
bun install
bun test
bun run typecheck
bun run deploy
```
