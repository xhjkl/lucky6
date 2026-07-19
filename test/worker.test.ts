import { describe, expect, it, vi } from "vitest";

import worker, {
  ProxyRequestError,
  assertPublicTarget,
  parseUpstreamUrl,
} from "../src/worker";

function capturedRequest(captured: { request: Request | null }): Request {
  if (captured.request == null) {
    throw new Error("Expected the Worker to issue an upstream request.");
  }
  return captured.request;
}

describe("parseUpstreamUrl", () => {
  it("decodes the scheme and host while preserving the path and query", () => {
    const upstreamUrl = parseUpstreamUrl(
      new URL("https://lucky6.example/https/api.jup.ag/swap/v2?x=1&y=two"),
    );

    expect(upstreamUrl.toString()).toBe(
      "https://api.jup.ag/swap/v2?x=1&y=two",
    );
  });

  it("supports HTTP, ports, and an omitted upstream path", () => {
    const upstreamUrl = parseUpstreamUrl(
      new URL("https://lucky6.example/http/example.com:8080"),
    );

    expect(upstreamUrl.toString()).toBe("http://example.com:8080/");
  });

  it("rejects embedded upstream credentials", () => {
    expect(() =>
      parseUpstreamUrl(
        new URL("https://lucky6.example/https/user:pass@example.com/path"),
      ),
    ).toThrow(ProxyRequestError);
  });
});

describe("assertPublicTarget", () => {
  it.each([
    "http://127.0.0.1/",
    "http://2130706433/",
    "http://10.1.2.3/",
    "http://169.254.169.254/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://metadata.google.internal/",
    "http://service.local/",
  ])("rejects non-public target %s", (target) => {
    expect(() =>
      assertPublicTarget(new URL(target), "lucky6.xhjkl.xyz"),
    ).toThrow(ProxyRequestError);
  });

  it.each([
    "https://api.jup.ag/",
    "https://1.1.1.1/",
    "https://[2606:4700:4700::1111]/",
  ])("accepts public target %s", (target) => {
    expect(() =>
      assertPublicTarget(new URL(target), "lucky6.xhjkl.xyz"),
    ).not.toThrow();
  });

  it("rejects a loop back into the proxy", () => {
    expect(() =>
      assertPublicTarget(
        new URL("https://lucky6.xhjkl.xyz/https/example.com"),
        "lucky6.xhjkl.xyz",
      ),
    ).toThrow("cannot target itself");
  });
});

describe("worker", () => {
  it("documents usage at GET /", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    const response = await worker.fetch(
      new Request("https://lucky6.xhjkl.xyz/"),
    );

    await expect(response.text()).resolves.toContain(
      "/https/api.jup.ag/swap/v2",
    );
    expect(response.status).toBe(200);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("forwards the method, body, auth, path, and query", async () => {
    const captured = { request: null as Request | null };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (request: Request) => {
        captured.request = request;
        return new Response("upstream", { status: 418 });
      }),
    );

    const request = new Request(
      "https://lucky6.xhjkl.xyz/https/api.jup.ag/swap/v2?userPublicKey=abc",
      {
        body: JSON.stringify({ quoteResponse: {} }),
        headers: {
          authorization: "Bearer client-key",
          "content-type": "application/json",
          "x-forwarded-for": "127.0.0.1",
        },
        method: "POST",
      },
    );

    const response = await worker.fetch(request);

    expect(response.status).toBe(418);
    const upstreamRequest = capturedRequest(captured);
    expect(upstreamRequest.url).toBe(
      "https://api.jup.ag/swap/v2?userPublicKey=abc",
    );
    expect(upstreamRequest.method).toBe("POST");
    expect(upstreamRequest.redirect).toBe("manual");
    expect(upstreamRequest.headers.get("authorization")).toBe(
      "Bearer client-key",
    );
    expect(upstreamRequest.headers.get("x-forwarded-for")).toBeNull();
    await expect(upstreamRequest.text()).resolves.toBe(
      JSON.stringify({ quoteResponse: {} }),
    );
  });

  it("returns the upstream response object without buffering it", async () => {
    const upstreamResponse = new Response("streamed", { status: 200 });
    vi.stubGlobal("fetch", vi.fn(async () => upstreamResponse));

    const response = await worker.fetch(
      new Request("https://lucky6.xhjkl.xyz/https/example.com/data"),
    );

    expect(response).toBe(upstreamResponse);
  });

  it("rejects private targets before fetch", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    const response = await worker.fetch(
      new Request("https://lucky6.xhjkl.xyz/http/127.0.0.1/admin"),
    );

    expect(response.status).toBe(400);
    await expect(response.text()).resolves.toContain("not public");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("turns fetch failures into an opaque gateway error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("sensitive runtime detail");
      }),
    );

    const response = await worker.fetch(
      new Request("https://lucky6.xhjkl.xyz/https/example.com/data"),
    );

    expect(response.status).toBe(502);
    await expect(response.text()).resolves.toBe("Upstream fetch failed.");
  });
});
