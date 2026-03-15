"use strict";

// Load Phantom config (defines self.__phantom$config)
importScripts("/phantom.config.js");
// Load BareMux client (used to make proxied HTTP requests through libcurl/wisp)
importScripts("/baremux/index.js");

const PREFIX = self.__phantom$config.prefix;
const encode = (url) => self.__phantom$config.encodeUrl(url);
const decode = (encoded) => self.__phantom$config.decodeUrl(encoded);

// ─────────────────────────────────────────────────────────────
//  INSTALL & ACTIVATE
// ─────────────────────────────────────────────────────────────

self.addEventListener("install", (event) => {
  // Take over immediately - no waiting for old SW to die
  event.waitUntil(self.skipWaiting());
});

self.addEventListener("activate", (event) => {
  // Control all open pages immediately
  event.waitUntil(self.clients.claim());
});

// ─────────────────────────────────────────────────────────────
//  FETCH INTERCEPTION
// ─────────────────────────────────────────────────────────────

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // Only intercept requests that are for proxied content
  if (!url.pathname.startsWith(PREFIX)) return;

  event.respondWith(handleRequest(event.request));
});

// ─────────────────────────────────────────────────────────────
//  MAIN REQUEST HANDLER
// ─────────────────────────────────────────────────────────────

async function handleRequest(request) {
  const url = new URL(request.url);

  // Extract the encoded target URL from the path
  // Strip query string from the encoded segment (query gets forwarded separately)
  const encodedSegment = url.pathname.slice(PREFIX.length).split("?")[0];

  // Decode the target URL
  let targetUrl;
  try {
    targetUrl = decode(encodedSegment);
    if (!targetUrl) throw new Error("Decoded to null");
    new URL(targetUrl); // throws if not a valid URL
  } catch (e) {
    return phantomError(400, "Invalid proxy URL", e.message);
  }

  const targetUrlObj = new URL(targetUrl);

  // Forward any query string from the proxy URL onto the target URL
  if (url.search) {
    const targetWithQuery = new URL(targetUrl);
    for (const [k, v] of url.searchParams) {
      targetWithQuery.searchParams.set(k, v);
    }
    targetUrl = targetWithQuery.toString();
  }

  // Build clean request headers
  const reqHeaders = buildRequestHeaders(request.headers, targetUrlObj, url);

  // Make the request through BareMux (uses libcurl-transport → wisp tunnel)
  let response;
  try {
    const client = new BareMux.BareClient();
    response = await client.fetch(targetUrl, {
      method: request.method,
      headers: reqHeaders,
      body: isBodyMethod(request.method) ? request.body : undefined,
      redirect: "manual", // We handle redirects ourselves
      credentials: "omit",
    });
  } catch (e) {
    return phantomError(502, "Proxy request failed", e.message);
  }

  // ── Handle redirects ──────────────────────────────────────
  if (isRedirect(response.status)) {
    const location = response.headers.get("location");
    if (location) {
      try {
        const redirectTarget = new URL(location, targetUrl).toString();
        const redirectHeaders = buildResponseHeaders(response.headers, targetUrlObj);
        redirectHeaders.set("location", PREFIX + encode(redirectTarget));
        return new Response(null, {
          status: response.status,
          headers: redirectHeaders,
        });
      } catch {}
    }
  }

  // ── Build response headers ────────────────────────────────
  const respHeaders = buildResponseHeaders(response.headers, targetUrlObj);
  const contentType = (response.headers.get("content-type") || "").toLowerCase();

  // ── Rewrite body by content type ─────────────────────────
  try {
    if (isHtml(contentType)) {
      const text = await response.text();
      const rewritten = rewriteHtml(text, targetUrl);
      respHeaders.delete("content-length");
      respHeaders.set("content-type", "text/html; charset=utf-8");
      return new Response(rewritten, { status: response.status, headers: respHeaders });

    } else if (isCss(contentType)) {
      const text = await response.text();
      const rewritten = rewriteCss(text, targetUrl);
      respHeaders.delete("content-length");
      return new Response(rewritten, { status: response.status, headers: respHeaders });

    } else if (isJs(contentType)) {
      const text = await response.text();
      const rewritten = rewriteJs(text, targetUrl);
      respHeaders.delete("content-length");
      return new Response(rewritten, { status: response.status, headers: respHeaders });

    } else if (isM3u8(contentType, targetUrl)) {
      const text = await response.text();
      const rewritten = rewriteM3u8(text, targetUrl);
      respHeaders.delete("content-length");
      return new Response(rewritten, { status: response.status, headers: respHeaders });

    } else {
      // All other content (images, video, audio, fonts, wasm, binary)
      // Stream directly through without touching - critical for performance
      return new Response(response.body, {
        status: response.status,
        headers: respHeaders,
      });
    }
  } catch (e) {
    return phantomError(500, "Body rewrite error", e.message);
  }
}

// ─────────────────────────────────────────────────────────────
//  HEADER UTILITIES
// ─────────────────────────────────────────────────────────────

const STRIP_REQUEST_HEADERS = new Set([
  "host",
  "origin",
  "referer",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "forwarded",
  "via",
]);

function buildRequestHeaders(headers, targetUrl, proxyUrl) {
  const result = {};

  for (const [key, value] of headers.entries()) {
    const lower = key.toLowerCase();
    if (STRIP_REQUEST_HEADERS.has(lower)) continue;
    result[key] = value;
  }

  // Set correct host/origin for the target so sites don't reject the request
  result["host"] = targetUrl.host;
  result["origin"] = targetUrl.origin;

  // Rewrite referer: decode it back to the real URL
  const rawReferer = headers.get("referer");
  if (rawReferer) {
    try {
      const refUrl = new URL(rawReferer);
      if (refUrl.pathname.startsWith(PREFIX)) {
        const decoded = decode(refUrl.pathname.slice(PREFIX.length).split("?")[0]);
        if (decoded) result["referer"] = decoded;
      }
    } catch {}
  }

  // Disable compression so we can rewrite text bodies without decompressing
  result["accept-encoding"] = "identity";

  return result;
}

const STRIP_RESPONSE_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-xss-protection",
  "cross-origin-resource-policy",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "strict-transport-security",
  "permissions-policy",
  "report-to",
  "nel",
  "expect-ct",
]);

function buildResponseHeaders(headers, targetUrl) {
  const result = new Headers();

  for (const [key, value] of headers.entries()) {
    const lower = key.toLowerCase();

    if (STRIP_RESPONSE_HEADERS.has(lower)) continue;

    // Rewrite Set-Cookie: remove domain and secure so cookies actually get stored
    if (lower === "set-cookie") {
      const rewritten = value
        .replace(/;\s*domain=[^;,]*/gi, "")
        .replace(/;\s*secure\b/gi, "")
        .replace(/;\s*samesite=[^;,]*/gi, "; SameSite=None");
      result.append("set-cookie", rewritten);
      continue;
    }

    result.set(key, value);
  }

  return result;
}

// ─────────────────────────────────────────────────────────────
//  CONTENT TYPE DETECTION
// ─────────────────────────────────────────────────────────────

function isHtml(ct) {
  return ct.includes("text/html");
}

function isCss(ct) {
  return ct.includes("text/css");
}

function isJs(ct) {
  return (
    ct.includes("javascript") ||
    ct.includes("ecmascript") ||
    ct.includes("application/x-javascript") ||
    ct.includes("text/jscript")
  );
}

function isM3u8(ct, url) {
  return (
    ct.includes("mpegurl") ||
    ct.includes("x-mpegurl") ||
    url.includes(".m3u8")
  );
}

function isRedirect(status) {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

function isBodyMethod(method) {
  const m = method.toUpperCase();
  return m !== "GET" && m !== "HEAD" && m !== "OPTIONS";
}

// ─────────────────────────────────────────────────────────────
//  URL REWRITING
// ─────────────────────────────────────────────────────────────

function rewriteUrl(url, base) {
  if (!url) return url;
  url = url.trim();

  // Skip non-rewritable URLs
  if (
    url.startsWith("data:") ||
    url.startsWith("blob:") ||
    url.startsWith("javascript:") ||
    url.startsWith("mailto:") ||
    url.startsWith("tel:") ||
    url.startsWith("#") ||
    url === "" ||
    url === "about:blank"
  ) {
    return url;
  }

  // Handle protocol-relative URLs: //example.com/path
  if (url.startsWith("//")) {
    try {
      const proto = new URL(base).protocol;
      url = proto + url;
    } catch {
      return url;
    }
  }

  try {
    const resolved = new URL(url, base).toString();
    if (!resolved.startsWith("http://") && !resolved.startsWith("https://")) {
      return url;
    }
    return PREFIX + encode(resolved);
  } catch {
    return url;
  }
}

// ─────────────────────────────────────────────────────────────
//  HTML REWRITING
// ─────────────────────────────────────────────────────────────

function rewriteHtml(html, base) {
  let baseUrl = base;

  // Remove integrity (SRI) — these would block our rewritten resources
  html = html.replace(/\s+integrity=["'][^"']*["']/gi, "");

  // Remove crossorigin attributes — causes issues with proxied resources
  html = html.replace(/\s+crossorigin(?:=["'][^"']*["'])?/gi, "");

  // Handle <base href="..."> — capture the base URL then remove the tag
  html = html.replace(/<base([^>]*)>/gi, (match, attrs) => {
    const m = attrs.match(/href=["']([^"']+)["']/i);
    if (m) {
      try { baseUrl = new URL(m[1], base).toString(); } catch {}
    }
    return "";
  });

  // Rewrite standard URL-bearing attributes
  const urlAttrs = ["src", "href", "action", "poster", "data", "background", "ping", "formaction"];
  for (const attr of urlAttrs) {
    html = html.replace(
      new RegExp(`(\\s${attr}=")([^"#][^"]*)(")`, "gi"),
      (m, pre, url, post) => pre + rewriteUrl(url, baseUrl) + post
    );
    html = html.replace(
      new RegExp(`(\\s${attr}=')([^'#][^']*)(')`, "gi"),
      (m, pre, url, post) => pre + rewriteUrl(url, baseUrl) + post
    );
  }

  // Rewrite srcset (comma-separated URL + optional descriptor)
  html = html.replace(/(\ssrcset=")([^"]*)(")/gi, (m, pre, srcset, post) => {
    return pre + rewriteSrcset(srcset, baseUrl) + post;
  });
  html = html.replace(/(\ssrcset=')([^']*)(')/gi, (m, pre, srcset, post) => {
    return pre + rewriteSrcset(srcset, baseUrl) + post;
  });

  // Rewrite inline style attributes
  html = html.replace(/(\sstyle=")([^"]*)(")/gi, (m, pre, style, post) => {
    return pre + rewriteCss(style, baseUrl) + post;
  });
  html = html.replace(/(\sstyle=')([^']*)(')/gi, (m, pre, style, post) => {
    return pre + rewriteCss(style, baseUrl) + post;
  });

  // Rewrite <style> blocks
  html = html.replace(/(<style[^>]*>)([\s\S]*?)(<\/style>)/gi, (m, open, css, close) => {
    return open + rewriteCss(css, baseUrl) + close;
  });

  // Rewrite <script> blocks (inline JS)
  html = html.replace(/(<script(?![^>]*src)[^>]*>)([\s\S]*?)(<\/script>)/gi, (m, open, js, close) => {
    return open + rewriteJs(js, baseUrl) + close;
  });

  // Rewrite meta refresh
  html = html.replace(
    /(<meta[^>]+http-equiv=["']refresh["'][^>]+content=["'][0-9]*;\s*url=)([^"'\s>]+)/gi,
    (m, pre, url) => pre + rewriteUrl(url, baseUrl)
  );

  // Inject Phantom client script as first thing in <head>
  // This ensures our overrides are in place before any page scripts run
  if (html.match(/<head[^>]*>/i)) {
    html = html.replace(
      /<head([^>]*)>/i,
      `<head$1><script src="/phantom.client.js"></script>`
    );
  } else if (html.match(/<html[^>]*>/i)) {
    html = html.replace(
      /<html([^>]*)>/i,
      `<html$1><script src="/phantom.client.js"></script>`
    );
  } else {
    html = `<script src="/phantom.client.js"></script>` + html;
  }

  return html;
}

function rewriteSrcset(srcset, base) {
  return srcset
    .split(",")
    .map((part) => {
      const trimmed = part.trim();
      const match = trimmed.match(/^(\S+)(\s.*)?$/);
      if (!match) return part;
      const [, url, descriptor = ""] = match;
      return rewriteUrl(url, base) + descriptor;
    })
    .join(", ");
}

// ─────────────────────────────────────────────────────────────
//  CSS REWRITING
// ─────────────────────────────────────────────────────────────

function rewriteCss(css, base) {
  // url() values
  css = css.replace(
    /url\(\s*(["']?)([^)'"]+)\1\s*\)/gi,
    (m, quote, url) => `url(${quote}${rewriteUrl(url, base)}${quote})`
  );
  // @import "url"
  css = css.replace(
    /@import\s+(["'])([^"']+)\1/gi,
    (m, quote, url) => `@import ${quote}${rewriteUrl(url, base)}${quote}`
  );
  return css;
}

// ─────────────────────────────────────────────────────────────
//  JAVASCRIPT REWRITING
// ─────────────────────────────────────────────────────────────

function rewriteJs(js, base) {
  if (!js.trim()) return js;

  // importScripts('url') — used in workers
  js = js.replace(
    /\bimportScripts\((["'])([^"']+)\1\)/g,
    (m, q, url) => `importScripts(${q}${rewriteUrl(url, base)}${q})`
  );

  // Static ES module imports: import ... from 'url'
  js = js.replace(
    /(import\s+[\s\S]*?from\s+)(["'])([^"']+)\2/g,
    (m, pre, q, url) => `${pre}${q}${rewriteUrl(url, base)}${q}`
  );

  // Dynamic import('url')
  js = js.replace(
    /\bimport\((["'])([^"']+)\1\)/g,
    (m, q, url) => `import(${q}${rewriteUrl(url, base)}${q})`
  );

  // export ... from 'url'
  js = js.replace(
    /(export\s+[\s\S]*?from\s+)(["'])([^"']+)\2/g,
    (m, pre, q, url) => `${pre}${q}${rewriteUrl(url, base)}${q}`
  );

  return js;
}

// ─────────────────────────────────────────────────────────────
//  M3U8 / HLS PLAYLIST REWRITING
// ─────────────────────────────────────────────────────────────

function rewriteM3u8(text, base) {
  return text
    .split("\n")
    .map((line) => {
      const trimmed = line.trim();

      // Directive lines — rewrite URI="" values
      if (trimmed.startsWith("#")) {
        return trimmed.replace(/URI=["']([^"']+)["']/g, (m, url) => {
          return `URI="${rewriteUrl(url, base)}"`;
        });
      }

      // Segment lines (non-empty, non-comment)
      if (trimmed && !trimmed.startsWith("#")) {
        return rewriteUrl(trimmed, base);
      }

      return line;
    })
    .join("\n");
}

// ─────────────────────────────────────────────────────────────
//  ERROR PAGE
// ─────────────────────────────────────────────────────────────

function phantomError(status, title, detail = "") {
  const body = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Phantom — ${status}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #080810;
      color: #f0eeff;
      font-family: 'Segoe UI', system-ui, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .box { text-align: center; padding: 40px; }
    .code {
      font-size: 72px;
      font-weight: 900;
      background: linear-gradient(135deg, #a78bfa, #ff5faa);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      line-height: 1;
    }
    .ghost { font-size: 48px; margin-bottom: 8px; }
    h2 { color: #f0eeff; margin: 12px 0 8px; font-size: 20px; }
    p { color: rgba(240,238,255,0.4); font-size: 13px; max-width: 400px; word-break: break-word; }
    a {
      display: inline-block;
      margin-top: 24px;
      color: #a78bfa;
      text-decoration: none;
      font-size: 14px;
    }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="box">
    <div class="ghost">👻</div>
    <div class="code">${status}</div>
    <h2>${title}</h2>
    <p>${detail}</p>
    <a href="/">← Back to Phantom</a>
  </div>
</body>
</html>`;

  return new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
                            }
  
