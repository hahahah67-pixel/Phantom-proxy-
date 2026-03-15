(function () {
  "use strict";

  // ── Config (must match phantom.config.js) ───────────────────
  const PREFIX = "/phantom/service/";
  const KEY = 0x26;

  function encode(url) {
    const xored = Array.from(url)
      .map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ ((KEY + i) % 256)))
      .join("");
    return btoa(xored).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  function decode(encoded) {
    try {
      let s = encoded.replace(/-/g, "+").replace(/_/g, "/");
      while (s.length % 4) s += "=";
      const dec = atob(s);
      return Array.from(dec)
        .map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ ((KEY + i) % 256)))
        .join("");
    } catch {
      return null;
    }
  }

  // ── Determine real URL of current page ──────────────────────
  const currentPath = location.pathname;
  let realUrl = location.href;
  let realOrigin = location.origin;
  let realBase = location.href;

  if (currentPath.startsWith(PREFIX)) {
    const decoded = decode(currentPath.slice(PREFIX.length).split("?")[0]);
    if (decoded) {
      realUrl = decoded;
      try {
        const u = new URL(decoded);
        realOrigin = u.origin;
        realBase = u.href;
      } catch {}
    }
  }

  // ── Core URL proxying function ───────────────────────────────
  function proxyUrl(url) {
    if (!url) return url;
    if (typeof url !== "string") {
      try { url = String(url); } catch { return url; }
    }
    url = url.trim();

    // Already proxied — don't double-encode
    if (url.startsWith(PREFIX)) return url;

    // Pass-through for non-proxiable URLs
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

    // Protocol-relative → add scheme from real page
    if (url.startsWith("//")) {
      try {
        url = new URL(realBase).protocol + url;
      } catch {
        return url;
      }
    }

    try {
      const resolved = new URL(url, realBase).toString();
      if (!resolved.startsWith("http://") && !resolved.startsWith("https://")) {
        return url;
      }
      return PREFIX + encode(resolved);
    } catch {
      return url;
    }
  }

  // ── history.pushState / replaceState ────────────────────────
  // Keeps URLs encoded in the address bar during SPA navigation
  const _pushState = history.pushState.bind(history);
  const _replaceState = history.replaceState.bind(history);

  history.pushState = function (state, title, url) {
    try {
      if (url != null) url = proxyUrl(String(url));
    } catch {}
    return _pushState(state, title, url);
  };

  history.replaceState = function (state, title, url) {
    try {
      if (url != null) url = proxyUrl(String(url));
    } catch {}
    return _replaceState(state, title, url);
  };

  // ── fetch override ───────────────────────────────────────────
  // Ensures JS-driven API calls also go through the proxy
  const _fetch = self.fetch.bind(self);
  self.fetch = function (input, init) {
    try {
      if (typeof input === "string") {
        input = proxyUrl(input);
      } else if (input instanceof URL) {
        input = proxyUrl(input.toString());
      } else if (typeof Request !== "undefined" && input instanceof Request) {
        if (!input.url.startsWith(PREFIX)) {
          const newUrl = proxyUrl(input.url);
          input = new Request(newUrl, {
            method: input.method,
            headers: input.headers,
            body: input.body,
            mode: input.mode === "navigate" ? "same-origin" : input.mode,
            credentials: input.credentials,
            redirect: input.redirect,
          });
        }
      }
    } catch {}
    return _fetch(input, init);
  };

  // ── XMLHttpRequest override ─────────────────────────────────
  const _XHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    try {
      url = proxyUrl(String(url));
    } catch {}
    return _XHROpen.call(this, method, url, ...rest);
  };

  // ── WebSocket override ──────────────────────────────────────
  // libcurl-transport tunnels WebSocket connections through Wisp automatically.
  // We keep this override to handle any edge cases and future-proof the setup.
  const _WS = self.WebSocket;
  if (_WS) {
    const PhantomWS = function (url, protocols) {
      if (protocols !== undefined) {
        return new _WS(url, protocols);
      }
      return new _WS(url);
    };
    PhantomWS.prototype = _WS.prototype;
    PhantomWS.CONNECTING = 0;
    PhantomWS.OPEN = 1;
    PhantomWS.CLOSING = 2;
    PhantomWS.CLOSED = 3;
    try { self.WebSocket = PhantomWS; } catch {}
  }

  // ── Worker / SharedWorker override ──────────────────────────
  // Ensures worker scripts are also fetched through the proxy
  const _Worker = self.Worker;
  if (_Worker) {
    const PhantomWorker = function (scriptURL, options) {
      try { scriptURL = proxyUrl(String(scriptURL)); } catch {}
      return options ? new _Worker(scriptURL, options) : new _Worker(scriptURL);
    };
    PhantomWorker.prototype = _Worker.prototype;
    try { self.Worker = PhantomWorker; } catch {}
  }

  const _SharedWorker = self.SharedWorker;
  if (_SharedWorker) {
    const PhantomSharedWorker = function (scriptURL, options) {
      try { scriptURL = proxyUrl(String(scriptURL)); } catch {}
      return options
        ? new _SharedWorker(scriptURL, options)
        : new _SharedWorker(scriptURL);
    };
    PhantomSharedWorker.prototype = _SharedWorker.prototype;
    try { self.SharedWorker = PhantomSharedWorker; } catch {}
  }

  // ── window.open override ────────────────────────────────────
  const _windowOpen = window.open.bind(window);
  window.open = function (url, target, features) {
    try {
      if (url) url = proxyUrl(String(url));
    } catch {}
    return _windowOpen(url, target, features);
  };

  // ── Prevent competing ServiceWorker registrations ───────────
  // Some sites try to register their own SWs which would interfere
  if ("serviceWorker" in navigator) {
    try {
      const _swRegister = navigator.serviceWorker.register.bind(
        navigator.serviceWorker
      );
      Object.defineProperty(navigator.serviceWorker, "register", {
        value: function (scriptURL, options) {
          try { scriptURL = proxyUrl(String(scriptURL)); } catch {}
          return _swRegister(scriptURL, options);
        },
        writable: true,
        configurable: true,
      });
    } catch {}
  }

  // ── EventSource override ─────────────────────────────────────
  // For server-sent events (SSE)
  const _EventSource = self.EventSource;
  if (_EventSource) {
    const PhantomEventSource = function (url, init) {
      try { url = proxyUrl(String(url)); } catch {}
      return init ? new _EventSource(url, init) : new _EventSource(url);
    };
    PhantomEventSource.prototype = _EventSource.prototype;
    try { self.EventSource = PhantomEventSource; } catch {}
  }

  // ── Expose for debugging ─────────────────────────────────────
  self.__phantom = {
    version: "1.0.0",
    encode,
    decode,
    proxyUrl,
    realUrl,
    realOrigin,
  };
})();
      
