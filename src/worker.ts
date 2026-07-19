const ROOT_MESSAGE = `lucky6 forwards HTTP requests from IPv6-capable Cloudflare to public upstreams.

Usage: /<http-or-https>/<host>/<path>?<query>
Example: /https/api.jup.ag/swap/v2

Private, local, reserved, and self-referential targets are rejected. Redirects are returned without being followed.`;

const BLOCKED_HOSTNAMES = new Set([
  "instance-data",
  "metadata.google.internal",
  "metadata.google",
]);

const BLOCKED_HOSTNAME_SUFFIXES = [
  ".example",
  ".home.arpa",
  ".internal",
  ".invalid",
  ".local",
  ".localhost",
  ".onion",
  ".test",
];

const FORWARDING_HEADERS = [
  "forwarded",
  "via",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
];

const HOP_BY_HOP_HEADERS = [
  "connection",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

const GLOBAL_IPV6_UNICAST = 0x20000000000000000000000000000000n;

const BLOCKED_IPV6_NETWORKS: ReadonlyArray<readonly [bigint, number]> = [
  [0x20010000000000000000000000000000n, 23],
  [0x20010db8000000000000000000000000n, 32],
  [0x20020000000000000000000000000000n, 16],
  [0x3fff0000000000000000000000000000n, 20],
];

/** Client input that cannot name a public upstream. */
export class ProxyRequestError extends Error {}

export default {
  async fetch(request: Request): Promise<Response> {
    const requestUrl = new URL(request.url);

    if (request.method === "GET" && requestUrl.pathname === "/") {
      return textResponse(ROOT_MESSAGE, 200);
    }

    if (request.headers.get("upgrade") != null) {
      return textResponse("WebSocket upgrades are not supported.", 400);
    }

    let upstreamUrl: URL;
    try {
      upstreamUrl = parseUpstreamUrl(requestUrl);
      assertPublicTarget(upstreamUrl, requestUrl.hostname);
    } catch (error) {
      if (error instanceof ProxyRequestError) {
        return textResponse(error.message, 400);
      }
      return textResponse("Invalid proxy URL.", 400);
    }

    const upstreamRequest = makeUpstreamRequest(request, upstreamUrl);

    try {
      // A proxy must not let one caller populate a shared edge cache for another.
      return await fetch(upstreamRequest, {
        cf: { cacheTtlByStatus: { "100-599": -1 } },
        redirect: "manual",
      });
    } catch {
      return textResponse("Upstream fetch failed.", 502);
    }
  },
};

/** Upstream URL encoded as /<scheme>/<authority>/<path> by the caller. */
export function parseUpstreamUrl(proxyUrl: URL): URL {
  const match = proxyUrl.pathname.match(/^\/(https?)\/([^/]+)(\/.*)?$/);
  if (match == null) {
    throw new ProxyRequestError(
      "Expected /<http-or-https>/<host>/<path>.",
    );
  }

  const scheme = match[1];
  const authority = match[2];
  const pathname = match[3] ?? "/";
  const upstreamUrl = new URL(`${scheme}://${authority}${pathname}`);

  if (upstreamUrl.username !== "" || upstreamUrl.password !== "") {
    throw new ProxyRequestError("Upstream credentials are not allowed in the URL.");
  }

  upstreamUrl.search = proxyUrl.search;
  return upstreamUrl;
}

/** Public Internet target, excluding names that could loop into this Worker. */
export function assertPublicTarget(upstreamUrl: URL, proxyHostname: string): void {
  const hostname = normalizeHostname(upstreamUrl.hostname);
  const ownHostname = normalizeHostname(proxyHostname);

  if (hostname === ownHostname) {
    throw new ProxyRequestError("The proxy cannot target itself.");
  }

  const ipv4 = parseIpv4(hostname);
  if (ipv4 != null) {
    if (isBlockedIpv4(ipv4)) {
      throw new ProxyRequestError("The upstream IP address is not public.");
    }
    return;
  }

  const ipv6 = parseIpv6(hostname);
  if (ipv6 != null) {
    if (isBlockedIpv6(ipv6)) {
      throw new ProxyRequestError("The upstream IP address is not public.");
    }
    return;
  }

  if (hostname.includes(":")) {
    throw new ProxyRequestError("Invalid upstream IP address.");
  }

  if (
    !hostname.includes(".") ||
    hostname === "localhost" ||
    BLOCKED_HOSTNAMES.has(hostname) ||
    BLOCKED_HOSTNAME_SUFFIXES.some(
      (suffix) => hostname === suffix.slice(1) || hostname.endsWith(suffix),
    )
  ) {
    throw new ProxyRequestError("The upstream hostname is not public.");
  }
}

/** Caller request retargeted without spoofable forwarding or hop-by-hop headers. */
function makeUpstreamRequest(request: Request, upstreamUrl: URL): Request {
  const upstreamRequest = new Request(upstreamUrl, request);

  for (const header of [...FORWARDING_HEADERS, ...HOP_BY_HOP_HEADERS]) {
    upstreamRequest.headers.delete(header);
  }

  return new Request(upstreamRequest, { redirect: "manual" });
}

function normalizeHostname(hostname: string): string {
  let normalized = hostname.toLowerCase();
  if (normalized.startsWith("[") && normalized.endsWith("]")) {
    normalized = normalized.slice(1, -1);
  }
  return normalized.replace(/\.+$/, "");
}

function parseIpv4(hostname: string): readonly [number, number, number, number] | null {
  const parts = hostname.split(".");
  if (parts.length !== 4) {
    return null;
  }

  const octets = parts.map((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return Number.NaN;
    }
    return Number(part);
  });

  if (octets.some((octet) => !Number.isInteger(octet) || octet > 255)) {
    return null;
  }

  const [a, b, c, d] = octets;
  if (a == null || b == null || c == null || d == null) {
    return null;
  }
  return [a, b, c, d];
}

function isBlockedIpv4(ipv4: readonly [number, number, number, number]): boolean {
  const [a, b, c] = ipv4;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function parseIpv6(hostname: string): bigint | null {
  if (!hostname.includes(":")) {
    return null;
  }

  const halves = hostname.split("::");
  if (halves.length > 2) {
    return null;
  }

  const left = parseIpv6Half(halves[0] ?? "");
  const right = parseIpv6Half(halves[1] ?? "");
  if (left == null || right == null) {
    return null;
  }

  const omitted = 8 - left.length - right.length;
  if (halves.length === 1 ? omitted !== 0 : omitted < 1) {
    return null;
  }

  const groups = [...left, ...Array<number>(omitted).fill(0), ...right];
  return groups.reduce((value, group) => (value << 16n) | BigInt(group), 0n);
}

function parseIpv6Half(half: string): number[] | null {
  if (half === "") {
    return [];
  }

  const groups: number[] = [];
  for (const part of half.split(":")) {
    if (!/^[0-9a-f]{1,4}$/i.test(part)) {
      return null;
    }
    groups.push(Number.parseInt(part, 16));
  }
  return groups;
}

function isBlockedIpv6(ipv6: bigint): boolean {
  return (
    !isIpv6InNetwork(ipv6, GLOBAL_IPV6_UNICAST, 3) ||
    BLOCKED_IPV6_NETWORKS.some(([network, prefix]) =>
      isIpv6InNetwork(ipv6, network, prefix),
    )
  );
}

function isIpv6InNetwork(ipv6: bigint, network: bigint, prefix: number): boolean {
  const shift = 128n - BigInt(prefix);
  return ipv6 >> shift === network >> shift;
}

function textResponse(message: string, status: number): Response {
  return new Response(message, {
    headers: {
      "cache-control": "no-store",
      "content-type": "text/plain; charset=utf-8",
    },
    status,
  });
}
