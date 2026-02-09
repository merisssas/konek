import type { ErrorLogBuffer, Logger } from "./logger.ts";
import type {
  ShadowsocksConfig,
  TrojanConfig,
  ProtocolCommandConfig,
} from "./config.ts";
import { maskIP, uuidToBytes } from "./utils.ts";

export type VlessServerOptions = {
  port: number;
  uuid: string;
  adminPassword: string;
  masqueradeUrl: string;
  dohUrl: string | null;
  shadowsocks: ShadowsocksConfig;
  trojan: TrojanConfig;
  protocolCommands: ProtocolCommandConfig;
  errorLogBuffer: ErrorLogBuffer;
  logger?: Logger;
};

const textDecoder = new TextDecoder();
const MEMORY_USAGE_LIMIT = 0.85;
const HANDSHAKE_TIMEOUT_MS = 5000;
const TCP_IDLE_TIMEOUT_MS = 30_000;
const TCP_IDLE_CHECK_INTERVAL_MS = 5_000;
const TARPIT_CONFIG = {
  minDelayMs: 1000,
  maxDelayMs: 4000,
  minBytes: 50,
  maxBytes: 300,
};
const MAX_WS_QUEUE_BYTES = 8 * 1024 * 1024;
const MAX_EARLY_DATA_BYTES = 64 * 1024;
const MAX_CONCURRENT_SESSIONS = 1000;
const SESSION_HIGH_WATER_MARK = Math.floor(MAX_CONCURRENT_SESSIONS * 0.9);
const MAX_UDP_DATAGRAM_SIZE = 1400;
const UDP_MAX_PACKETS_PER_SECOND = 200;
const UDP_BURST_PACKETS = 400;
const UDP_MAX_BYTES_PER_SECOND = UDP_MAX_PACKETS_PER_SECOND *
  MAX_UDP_DATAGRAM_SIZE;
const UDP_BURST_BYTES = UDP_BURST_PACKETS * MAX_UDP_DATAGRAM_SIZE;
const UDP_IDLE_TIMEOUT_MS = 15_000;
const UDP_IDLE_CHECK_INTERVAL_MS = 1_000;
const DNS_CACHE_TTL_MS = 60_000;
const DNS_CACHE_MAX_ENTRIES = 500;
const DNS_MAX_RESOLVES_PER_SESSION = 4;
const DOH_TIMEOUT_MS = 1500;
const DNS_FALLBACK_TIMEOUT_MS = 2500;
const PROXY_MAX_BODY_BYTES = 1024 * 1024;

const ALLOWED_MASQUERADE_METHODS = new Set(["GET", "HEAD", "POST"]);
const REDACTED_REQUEST_HEADERS = new Set([
  "origin",
  "referer",
  "sec-fetch-site",
  "sec-fetch-mode",
  "sec-fetch-dest",
  "sec-fetch-user",
]);

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "upgrade",
  "proxy-connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "proxy-authenticate",
  "proxy-authorization",
]);

const FORWARDED_HEADER_PREFIXES = [
  "x-forwarded-",
  "cf-",
  "true-client-",
  "forwarded",
];

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

type DnsCacheEntry = {
  value: string | null;
  expiresAt: number;
};

type SessionState = {
  resolveCount: number;
};

type SessionLimiter = {
  tryAcquire: () => (() => void) | null;
  active: () => number;
};

const dnsCache = new Map<string, DnsCacheEntry>();

type LoadAdvisor = {
  isHighLoad: () => boolean;
};

function createSessionLimiter(maxSessions: number): SessionLimiter {
  let activeSessions = 0;
  return {
    tryAcquire: () => {
      if (activeSessions >= maxSessions) {
        return null;
      }
      activeSessions += 1;
      let released = false;
      return () => {
        if (released) {
          return;
        }
        released = true;
        activeSessions = Math.max(0, activeSessions - 1);
      };
    },
    active: () => activeSessions,
  };
}

export function startVlessServer(options: VlessServerOptions): void {
  const validUUIDBytes = uuidToBytes(options.uuid);
  if (!validUUIDBytes) {
    throw new Error("UUID is not valid");
  }
  const logger = options.logger ?? console;
  const sessionLimiter = createSessionLimiter(MAX_CONCURRENT_SESSIONS);
  logger.info(`🚀 VLESS server listening on :${options.port} [UDP: ON]`);
  startTcpProtocolService(
    "shadowsocks",
    options.shadowsocks.port,
    logger,
    options.protocolCommands.shadowsocks,
  );
  startTcpProtocolService(
    "trojan",
    options.trojan.port,
    logger,
    options.protocolCommands.trojan,
  );

  Deno.serve({ port: options.port }, async (req) => {
    if (isMemoryPressure(MEMORY_USAGE_LIMIT)) {
      logger.warn("High memory usage detected, rejecting request.");
      return new Response("Service Unavailable", { status: 503 });
    }
    const upgrade = req.headers.get("upgrade") || "";
    if (upgrade.toLowerCase() !== "websocket") {
      return handleHttpRequest(req, options, logger);
    }

    const { earlyData, protocol } = parseWebSocketProtocolHeader(
      req.headers.get("sec-websocket-protocol") || "",
    );
    if (earlyData && earlyData.byteLength > MAX_EARLY_DATA_BYTES) {
      return new Response("Payload Too Large", { status: 413 });
    }
    const releaseSession = sessionLimiter.tryAcquire();
    if (!releaseSession) {
      return new Response("Service Unavailable", { status: 503 });
    }
    const { socket, response } = Deno.upgradeWebSocket(
      req,
      protocol ? { protocol } : undefined,
    );

    socket.onopen = () => {
      processVlessSession(
        socket,
        validUUIDBytes,
        earlyData,
        options.dohUrl,
        logger,
        {
          isHighLoad: () =>
            sessionLimiter.active() >= SESSION_HIGH_WATER_MARK ||
            isMemoryPressure(MEMORY_USAGE_LIMIT),
        },
      );
    };
    socket.addEventListener("close", () => {
      releaseSession();
    }, { once: true });
    socket.addEventListener("error", () => {
      releaseSession();
    }, { once: true });

    return response;
  });
}

function isMemoryPressure(limit: number): boolean {
  const cgroup = readCgroupMemoryInfo();
  if (cgroup && cgroup.max > 0) {
    const usageRatio = cgroup.current / cgroup.max;
    return usageRatio >= limit;
  }
  const info = Deno.systemMemoryInfo();
  if (info.total <= 0) {
    return false;
  }
  const available = info.available > 0 ? info.available : info.free;
  const usageRatio = (info.total - available) / info.total;
  return usageRatio >= limit;
}

function readCgroupMemoryInfo():
  | { current: number; max: number }
  | null {
  const v2Current = readNumberFromFile("/sys/fs/cgroup/memory.current");
  const v2Max = readNumberFromFile("/sys/fs/cgroup/memory.max", true);
  if (v2Current !== null && v2Max !== null && v2Max > 0) {
    return { current: v2Current, max: v2Max };
  }
  const v1Current = readNumberFromFile(
    "/sys/fs/cgroup/memory/memory.usage_in_bytes",
  );
  const v1Max = readNumberFromFile(
    "/sys/fs/cgroup/memory/memory.limit_in_bytes",
  );
  if (v1Current !== null && v1Max !== null && v1Max > 0) {
    return { current: v1Current, max: v1Max };
  }
  return null;
}

function readNumberFromFile(
  path: string,
  allowMaxToken = false,
): number | null {
  try {
    const raw = Deno.readTextFileSync(path).trim();
    if (!raw) {
      return null;
    }
    if (allowMaxToken && raw === "max") {
      return Number.MAX_SAFE_INTEGER;
    }
    const value = Number(raw);
    if (!Number.isFinite(value)) {
      return null;
    }
    return value;
  } catch (_) {
    return null;
  }
}

async function handleHttpRequest(
  req: Request,
  options: VlessServerOptions,
  logger: Logger,
): Promise<Response> {
  const url = new URL(req.url);
  if (url.pathname === "/" || url.pathname === "/index.html") {
    return Response.redirect(options.masqueradeUrl, 302);
  }
  if (url.pathname === "/error") {
    const password = url.searchParams.get("password");
    if (password !== options.adminPassword) {
      return new Response("Unauthorized", { status: 401 });
    }
    return new Response(formatErrorLogs(options.errorLogBuffer), {
      status: 200,
      headers: { "Content-Type": "text/plain;charset=utf-8" },
    });
  }
  if (url.pathname === "/info") {
    const password = url.searchParams.get("password");
    if (password !== options.adminPassword) {
      return new Response("Unauthorized", { status: 401 });
    }
    return new Response(formatServerInfo(options), {
      status: 200,
      headers: { "Content-Type": "application/json;charset=utf-8" },
    });
  }
  if (url.pathname === "/config") {
    const password = url.searchParams.get("password");
    if (password !== options.adminPassword) {
      return new Response("Unauthorized", { status: 401 });
    }
    const port = url.port || (url.protocol === "https:" ? "443" : "80");
    const vlessConfig = getVLESSConfig(
      options.uuid,
      url.hostname,
      port,
      options.shadowsocks,
      options.trojan,
    );
    return new Response(`${vlessConfig}`, {
      status: 200,
      headers: { "Content-Type": "text/plain;charset=utf-8" },
    });
  }
  if (url.pathname === `/${options.uuid}`) {
    const port = url.port || (url.protocol === "https:" ? "443" : "80");
    const vlessConfig = getVLESSConfig(
      options.uuid,
      url.hostname,
      port,
      options.shadowsocks,
      options.trojan,
    );
    return new Response(`${vlessConfig}`, {
      status: 200,
      headers: { "Content-Type": "text/plain;charset=utf-8" },
    });
  }
  return await proxyMasquerade(req, options.masqueradeUrl, logger);
}

async function proxyMasquerade(
  req: Request,
  masqueradeUrl: string,
  logger: Logger,
): Promise<Response> {
  const method = req.method.toUpperCase();
  if (!ALLOWED_MASQUERADE_METHODS.has(method)) {
    return new Response("Method Not Allowed", { status: 405 });
  }
  if (req.headers.has("content-length") && req.headers.has("transfer-encoding")) {
    return new Response("Bad Request", { status: 400 });
  }
  const incomingUrl = new URL(req.url);
  const targetUrl = new URL(masqueradeUrl);
  targetUrl.pathname = incomingUrl.pathname;
  targetUrl.search = incomingUrl.search;

  const headers = filterRequestHeaders(req.headers);
  headers.delete("accept-encoding");
  headers.set("host", targetUrl.host);
  const contentLength = req.headers.get("content-length");
  if (contentLength && Number(contentLength) > PROXY_MAX_BODY_BYTES) {
    return new Response("Payload Too Large", { status: 413 });
  }
  const body = req.body
    ? limitRequestBody(req.body, PROXY_MAX_BODY_BYTES)
    : undefined;

  const outboundRequest = new Request(targetUrl.toString(), {
    method,
    headers,
    body,
    redirect: "follow",
  });

  try {
    const response = await fetch(outboundRequest);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: filterResponseHeaders(response.headers),
    });
  } catch (error) {
    if (error instanceof Error && error.message === "Request body too large") {
      return new Response("Payload Too Large", { status: 413 });
    }
    logger.error("Masquerade proxy failed", error);
    return new Response("Service Unavailable", { status: 503 });
  }
}

async function processVlessSession(
  ws: WebSocket,
  validUUIDBytes: Uint8Array,
  earlyData: ArrayBuffer | undefined,
  dohUrl: string | null,
  logger: Logger,
  loadAdvisor: LoadAdvisor,
) {
  let vlessHeaderProcessed = false;
  let handshakeBuffer = new Uint8Array(0);
  const sessionState: SessionState = { resolveCount: 0 };
  let wsReader: ReadableStreamDefaultReader<Uint8Array> | null = null;

  const handshakeTimer = setTimeout(() => {
    if (!vlessHeaderProcessed) {
      logger.warn("VLESS handshake timeout.");
      if (wsReader) {
        wsReader.cancel("handshake timeout").catch(() => {});
      }
      try {
        ws.close();
      } catch (_) {}
    }
  }, HANDSHAKE_TIMEOUT_MS);

  const wsStream = createWebSocketReadableStream(ws, earlyData, logger);
  wsReader = wsStream.getReader();

  try {
    while (true) {
      const { value, done } = await wsReader.read();
      if (done) break;
      const chunk = value;

      if (!vlessHeaderProcessed) {
        handshakeBuffer = appendBuffer(handshakeBuffer, chunk);
        const parsed = parseVlessHeader(handshakeBuffer, validUUIDBytes, logger);
        if (parsed.status === "need_more") {
          continue;
        }
        if (parsed.status === "invalid") {
          await tarpitAndClose(ws, loadAdvisor);
          return;
        }

        const resolvedTarget = await resolveTargetAddress(
          parsed.address,
          dohUrl,
          logger,
          sessionState,
        );
        if (!resolvedTarget || isBlockedAddress(resolvedTarget)) {
          logger.warn("Blocked or unresolved target request.");
          ws.close();
          return;
        }

        const vlessResponse = new Uint8Array([handshakeBuffer[0], 0]);
        if (!sendWebSocketMessage(ws, vlessResponse, logger, "handshake")) {
          safeCloseWebSocket(ws);
          return;
        }

        vlessHeaderProcessed = true;
        clearTimeout(handshakeTimer);
        const payload = handshakeBuffer.subarray(parsed.payloadOffset);
        handshakeBuffer = new Uint8Array(0);

        wsReader.releaseLock();
        const combinedStream = createCombinedStream(payload, wsStream);

        if (parsed.command === 1) {
          await handleTcpPipe(
            ws,
            combinedStream,
            resolvedTarget,
            parsed.port,
            logger,
          );
        } else if (parsed.command === 2) {
          await handleUdpPipe(
            ws,
            combinedStream,
            resolvedTarget,
            parsed.port,
            logger,
          );
        }
        return;
      }
    }
  } catch (err) {
    logger.warn("VLESS handshake error", err);
    try {
      ws.close();
    } catch (_) {}
  } finally {
    clearTimeout(handshakeTimer);
  }
}

function activityTransform(onActivity: () => void) {
  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      onActivity();
      controller.enqueue(chunk);
    },
  });
}

function createTokenBucket(ratePerSecond: number, burst: number) {
  let tokens = burst;
  let lastRefill = Date.now();
  return {
    consume(amount: number) {
      const now = Date.now();
      const elapsed = (now - lastRefill) / 1000;
      if (elapsed > 0) {
        tokens = Math.min(burst, tokens + elapsed * ratePerSecond);
        lastRefill = now;
      }
      if (tokens < amount) {
        return false;
      }
      tokens -= amount;
      return true;
    },
  };
}

async function handleTcpPipe(
  ws: WebSocket,
  inputStream: ReadableStream<Uint8Array>,
  address: string,
  port: number,
  logger: Logger,
) {
  let remoteConn: Deno.TcpConn;
  let closed = false;
  try {
    remoteConn = await Deno.connect({ hostname: address, port });
    try {
      remoteConn.setNoDelay(true);
    } catch (_) {}
    try {
      remoteConn.setKeepAlive(true);
    } catch (_) {}
  } catch (error) {
    logger.warn(`TCP connect failed: ${maskIP(address)}:${port}`, error);
    try {
      ws.close();
    } catch (_) {}
    return;
  }

  const closeAll = () => {
    if (closed) return;
    closed = true;
    try {
      if (!inputStream.locked) {
        inputStream.cancel("tcp closed");
      }
    } catch (_) {}
    try {
      remoteConn.close();
    } catch (_) {}
    try {
      ws.close();
    } catch (_) {}
  };

  let lastActivity = Date.now();
  const markActivity = () => {
    lastActivity = Date.now();
  };
  const idleChecker = setInterval(() => {
    if (Date.now() - lastActivity > TCP_IDLE_TIMEOUT_MS) {
      logger.info("TCP idle timeout reached, closing connection.");
      closeAll();
    }
  }, TCP_IDLE_CHECK_INTERVAL_MS);

  const wsWritable = new WritableStream<Uint8Array>({
    write(chunk) {
      if (ws.readyState === WebSocket.OPEN) {
        markActivity();
        if (!sendWebSocketMessage(ws, chunk, logger, "tcp->ws")) {
          closeAll();
        }
      }
    },
    close() {
      safeCloseWebSocket(ws);
    },
    abort() {
      safeCloseWebSocket(ws);
    },
  });

  try {
    const remoteToWs = remoteConn.readable
      .pipeThrough(activityTransform(markActivity))
      .pipeTo(wsWritable)
      .catch(() => {});
    const wsToRemote = inputStream
      .pipeThrough(activityTransform(markActivity))
      .pipeTo(remoteConn.writable)
      .catch(() => {});

    await Promise.race([remoteToWs, wsToRemote]);
    closeAll();
    await Promise.all([remoteToWs, wsToRemote]).catch(() => {});
  } finally {
    clearInterval(idleChecker);
    closeAll();
  }
}

async function handleUdpPipe(
  ws: WebSocket,
  inputStream: ReadableStream<Uint8Array>,
  address: string,
  port: number,
  logger: Logger,
) {
  const udpConn = Deno.listenDatagram({
    port: 0,
    transport: "udp",
    hostname: "127.0.0.1",
  });
  let closed = false;
  let lastActivity = Date.now();
  const outboundPacketLimiter = createTokenBucket(
    UDP_MAX_PACKETS_PER_SECOND,
    UDP_BURST_PACKETS,
  );
  const inboundPacketLimiter = createTokenBucket(
    UDP_MAX_PACKETS_PER_SECOND,
    UDP_BURST_PACKETS,
  );
  const outboundByteLimiter = createTokenBucket(
    UDP_MAX_BYTES_PER_SECOND,
    UDP_BURST_BYTES,
  );
  const inboundByteLimiter = createTokenBucket(
    UDP_MAX_BYTES_PER_SECOND,
    UDP_BURST_BYTES,
  );

  const closeAll = () => {
    if (closed) {
      return;
    }
    closed = true;
    try {
      if (!inputStream.locked) {
        inputStream.cancel("udp closed");
      }
    } catch (_) {}
    try {
      udpConn.close();
    } catch (_) {}
    try {
      ws.close();
    } catch (_) {}
  };

  const markActivity = () => {
    lastActivity = Date.now();
  };

  const idleChecker = setInterval(() => {
    if (Date.now() - lastActivity > UDP_IDLE_TIMEOUT_MS) {
      logger.info("UDP idle timeout reached, closing connection.");
      closeAll();
    }
  }, UDP_IDLE_CHECK_INTERVAL_MS);

  const wsToUdp = async () => {
    const reader = inputStream.getReader();
    let buffer = new Uint8Array(0);
    let dropRemaining = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          break;
        }
        if (!value) {
          continue;
        }
        markActivity();
        buffer = appendBuffer(buffer, value);
        while (buffer.length >= 2) {
          if (dropRemaining > 0) {
            const dropSize = Math.min(dropRemaining, buffer.length);
            buffer = buffer.subarray(dropSize);
            dropRemaining -= dropSize;
            if (buffer.length < 2) {
              break;
            }
            continue;
          }
          const size = (buffer[0] << 8) | buffer[1];
          if (size === 0) {
            buffer = buffer.subarray(2);
            continue;
          }
          if (size > MAX_UDP_DATAGRAM_SIZE) {
            buffer = buffer.subarray(2);
            if (buffer.length >= size) {
              buffer = buffer.subarray(size);
            } else {
              dropRemaining = size - buffer.length;
              buffer = new Uint8Array(0);
            }
            continue;
          }
          if (buffer.length < 2 + size) {
            break;
          }
          const payload = buffer.subarray(2, 2 + size);
          buffer = buffer.subarray(2 + size);
          if (
            !outboundPacketLimiter.consume(1) ||
            !outboundByteLimiter.consume(payload.length)
          ) {
            continue;
          }
          await udpConn.send(payload, {
            transport: "udp",
            hostname: address,
            port,
          });
        }
      }
    } catch (error) {
      logger.warn("UDP send failed", error);
    } finally {
      reader.releaseLock();
    }
  };

  const udpToWs = async () => {
    try {
      for await (const [data] of udpConn) {
        markActivity();
        if (data.length > MAX_UDP_DATAGRAM_SIZE) {
          continue;
        }
        if (
          !inboundPacketLimiter.consume(1) ||
          !inboundByteLimiter.consume(data.length)
        ) {
          continue;
        }
        if (ws.readyState === WebSocket.OPEN) {
          // Custom UDP framing over WS: 2-byte big-endian length prefix.
          const framed = new Uint8Array(2 + data.length);
          framed[0] = (data.length >> 8) & 0xff;
          framed[1] = data.length & 0xff;
          framed.set(data, 2);
          if (!sendWebSocketMessage(ws, framed, logger, "udp->ws")) {
            break;
          }
        } else {
          break;
        }
      }
    } catch (error) {
      logger.warn("UDP receive failed", error);
    }
  };

  try {
    await Promise.race([wsToUdp(), udpToWs()]);
  } finally {
    clearInterval(idleChecker);
    closeAll();
  }
}

function createCombinedStream(
  head: Uint8Array,
  bodyStream: ReadableStream<Uint8Array>,
): ReadableStream<Uint8Array> {
  if (head.length === 0) {
    return bodyStream;
  }
  const bodyReader = bodyStream.getReader();
  let headSent = false;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (!headSent) {
        controller.enqueue(head);
        headSent = true;
        return;
      }
      const { value, done } = await bodyReader.read();
      if (done) {
        controller.close();
        bodyReader.releaseLock();
        return;
      }
      if (value) {
        controller.enqueue(value);
      }
    },
    cancel(reason) {
      bodyReader.cancel(reason).catch(() => {});
    },
  });
}

async function tarpitAndClose(ws: WebSocket, loadAdvisor: LoadAdvisor) {
  if (ws.readyState !== WebSocket.OPEN) {
    return;
  }
  if (loadAdvisor.isHighLoad()) {
    try {
      ws.close();
    } catch (_) {}
    return;
  }
  const garbageSize = Math.floor(
    Math.random() * (TARPIT_CONFIG.maxBytes - TARPIT_CONFIG.minBytes + 1),
  ) + TARPIT_CONFIG.minBytes;
  const garbage = new Uint8Array(garbageSize);
  crypto.getRandomValues(garbage);
  if (!sendWebSocketMessage(ws, garbage, null, "tarpit")) {
    safeCloseWebSocket(ws);
    return;
  }
  const randomDelay = Math.floor(
    Math.random() *
      (TARPIT_CONFIG.maxDelayMs - TARPIT_CONFIG.minDelayMs + 1),
  ) + TARPIT_CONFIG.minDelayMs;
  await delay(randomDelay);
  ws.close();
}

function sendWebSocketMessage(
  ws: WebSocket,
  data: Uint8Array,
  logger: Logger | null,
  context: string,
): boolean {
  if (ws.readyState !== WebSocket.OPEN) {
    return false;
  }
  try {
    ws.send(data);
    return true;
  } catch (error) {
    if (logger) {
      logger.warn(`WebSocket send failed (${context})`, error);
    }
    return false;
  }
}

function safeCloseWebSocket(ws: WebSocket) {
  try {
    ws.close();
  } catch (_) {}
}

function parseWebSocketProtocolHeader(
  headerValue: string,
): { earlyData?: ArrayBuffer; protocol?: string } {
  const tokens = headerValue
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  for (const token of tokens) {
    const { earlyData } = base64ToArrayBuffer(token);
    if (earlyData) {
      return { earlyData, protocol: token };
    }
  }
  if (tokens.length > 0) {
    return { protocol: tokens[0] };
  }
  return {};
}

function base64ToArrayBuffer(base64Str: string): { earlyData?: ArrayBuffer } {
  if (!base64Str) {
    return {};
  }
  try {
    const normalized = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = atob(normalized);
    const bytes = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
    return { earlyData: bytes.buffer };
  } catch (_) {
    return {};
  }
}

function getVLESSConfig(
  userID: string,
  hostName: string,
  port: string,
  shadowsocks: ShadowsocksConfig,
  trojan: TrojanConfig,
): string {
  const vlessMain =
    `vless://${userID}\u0040${hostName}:${port}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${hostName}`;
  const shadowsocksUserInfo = base64Encode(
    `${shadowsocks.method}:${shadowsocks.password}`,
  );
  const shadowsocksLink =
    `ss://${shadowsocksUserInfo}\u0040${hostName}:${shadowsocks.port}#${hostName}-ss`;
  const trojanLink =
    `trojan://${trojan.password}\u0040${hostName}:${trojan.port}?sni=${hostName}&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${hostName}-trojan`;
  return `
################################################################
v2ray
---------------------------------------------------------------
${vlessMain}
${shadowsocksLink}
${trojanLink}
---------------------------------------------------------------
################################################################
clash-meta
---------------------------------------------------------------
- type: vless
  name: ${hostName}
  server: ${hostName}
  port: ${port}
  uuid: ${userID}
  network: ws
  tls: true
  udp: true
  sni: ${hostName}
  client-fingerprint: chrome
  ws-opts:
    path: "/?ed=2048"
    headers:
      host: ${hostName}
---------------------------------------------------------------
- type: ss
  name: ${hostName}-ss
  server: ${hostName}
  port: ${shadowsocks.port}
  cipher: ${shadowsocks.method}
  password: ${shadowsocks.password}
  udp: true
---------------------------------------------------------------
- type: trojan
  name: ${hostName}-trojan
  server: ${hostName}
  port: ${trojan.port}
  password: ${trojan.password}
  udp: true
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2048"
    headers:
      host: ${hostName}
---------------------------------------------------------------
################################################################
`;
}

function base64Encode(value: string): string {
  return btoa(value);
}

function startTcpProtocolService(
  name: string,
  port: number,
  logger: Logger,
  command?: string,
) {
  if (command?.trim()) {
    startExternalCommand(name, command, logger);
    return;
  }
  startTcpProtocolListener(name, port, logger);
}

function startExternalCommand(
  name: string,
  command: string,
  logger: Logger,
) {
  const parts = parseCommand(command);
  if (parts.length === 0) {
    logger.warn(`${name} command is empty, falling back to dummy listener`);
    return;
  }
  const [cmd, ...args] = parts;
  logger.info(`${name} daemon starting: ${command}`);
  try {
    const process = new Deno.Command(cmd, {
      args,
      stdin: "null",
      stdout: "piped",
      stderr: "piped",
    }).spawn();
    pipeProcessOutput(process, name, logger);
  } catch (error) {
    logger.error(`${name} daemon failed to start`, error);
  }
}

function pipeProcessOutput(
  process: Deno.ChildProcess,
  name: string,
  logger: Logger,
) {
  const decoder = new TextDecoder();
  const logStream = async (
    stream: ReadableStream<Uint8Array> | null,
    level: "info" | "error",
  ) => {
    if (!stream) return;
    try {
      for await (const chunk of stream) {
        const text = decoder.decode(chunk).trim();
        if (text) {
          logger[level](`[${name}] ${text}`);
        }
      }
    } catch (error) {
      logger.warn(`${name} daemon log stream failed`, error);
    }
  };
  logStream(process.stdout, "info");
  logStream(process.stderr, "error");
  process.status.then((status) => {
    if (status.success) {
      logger.info(`${name} daemon exited`);
    } else {
      logger.warn(`${name} daemon exited with code ${status.code}`);
    }
  }).catch((error) => {
    logger.error(`${name} daemon status error`, error);
  });
}

function parseCommand(command: string): string[] {
  const parts: string[] = [];
  let current = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let escapeNext = false;

  for (const char of command) {
    if (escapeNext) {
      current += char;
      escapeNext = false;
      continue;
    }
    if (char === "\\") {
      escapeNext = true;
      continue;
    }
    if (char === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
      continue;
    }
    if (char === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
      continue;
    }
    if (!inSingleQuote && !inDoubleQuote && /\s/.test(char)) {
      if (current) {
        parts.push(current);
        current = "";
      }
      continue;
    }
    current += char;
  }
  if (current) {
    parts.push(current);
  }
  return parts;
}

function startTcpProtocolListener(
  name: string,
  port: number,
  logger: Logger,
) {
  let listener: Deno.Listener;
  try {
    listener = Deno.listen({ port });
  } catch (error) {
    logger.warn(`${name} listener failed to start on :${port}`, error);
    return;
  }
  logger.info(`${name} listener running on :${port}`);
  (async () => {
    for await (const conn of listener) {
      conn.close();
    }
  })().catch((error) => {
    logger.error(`${name} listener failed`, error);
  });
}

function formatErrorLogs(errorLogBuffer: ErrorLogBuffer): string {
  const errors = errorLogBuffer.getRecentErrors();
  if (errors.length === 0) {
    return "No errors recorded.";
  }
  return errors.join("\n");
}

function formatServerInfo(options: VlessServerOptions): string {
  const memory = Deno.systemMemoryInfo();
  const info = {
    generatedAt: new Date().toISOString(),
    runtime: {
      deno: Deno.version,
      build: Deno.build,
    },
    process: {
      pid: Deno.pid,
      cwd: Deno.cwd(),
    },
    memory,
    config: {
      port: options.port,
      uuid: options.uuid,
      masqueradeUrl: options.masqueradeUrl,
      dohUrl: options.dohUrl,
      shadowsocks: {
        port: options.shadowsocks.port,
        method: options.shadowsocks.method,
      },
      trojan: {
        port: options.trojan.port,
      },
      protocolCommands: options.protocolCommands,
    },
    errors: {
      count: options.errorLogBuffer.size(),
    },
  };
  return JSON.stringify(info, null, 2);
}

function appendBuffer(buffer: Uint8Array, chunk: Uint8Array): Uint8Array {
  if (buffer.length === 0) {
    return chunk;
  }
  const merged = new Uint8Array(buffer.length + chunk.length);
  merged.set(buffer);
  merged.set(chunk, buffer.length);
  return merged;
}

function parseVlessHeader(
  buffer: Uint8Array,
  validUUIDBytes: Uint8Array,
  logger: Logger,
): {
  status: "need_more" | "invalid" | "ok";
  command?: number;
  port?: number;
  address?: string;
  payloadOffset?: number;
} {
  if (buffer.length < 18) {
    return { status: "need_more" };
  }

  const clientUUID = buffer.subarray(1, 17);
  for (let i = 0; i < 16; i++) {
    if (clientUUID[i] !== validUUIDBytes[i]) {
      logger.debug("UUID mismatch");
      return { status: "invalid" };
    }
  }

  const addonsLen = buffer[17];
  const commandIndex = 18 + addonsLen;
  if (buffer.length <= commandIndex) {
    return { status: "need_more" };
  }
  const command = buffer[commandIndex];
  if (command !== 1 && command !== 2) {
    logger.warn(`Unsupported command: ${command}`);
    return { status: "invalid" };
  }

  const portIndex = commandIndex + 1;
  if (buffer.length <= portIndex + 1) {
    return { status: "need_more" };
  }
  const port = (buffer[portIndex] << 8) | buffer[portIndex + 1];

  const addrTypeIndex = portIndex + 2;
  if (buffer.length <= addrTypeIndex) {
    return { status: "need_more" };
  }

  const addrType = buffer[addrTypeIndex];
  let address = "";
  let addressEndIndex = 0;

  if (addrType === 1) {
    addressEndIndex = addrTypeIndex + 1 + 4;
    if (buffer.length < addressEndIndex) {
      return { status: "need_more" };
    }
    address = buffer.subarray(addrTypeIndex + 1, addressEndIndex).join(".");
  } else if (addrType === 2) {
    if (buffer.length <= addrTypeIndex + 1) {
      return { status: "need_more" };
    }
    const domainLen = buffer[addrTypeIndex + 1];
    addressEndIndex = addrTypeIndex + 2 + domainLen;
    if (buffer.length < addressEndIndex) {
      return { status: "need_more" };
    }
    const domainBytes = buffer.subarray(addrTypeIndex + 2, addressEndIndex);
    address = textDecoder.decode(domainBytes);
  } else if (addrType === 3) {
    addressEndIndex = addrTypeIndex + 1 + 16;
    if (buffer.length < addressEndIndex) {
      return { status: "need_more" };
    }
    const view = new DataView(
      buffer.buffer,
      buffer.byteOffset + addrTypeIndex + 1,
      16,
    );
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(view.getUint16(i * 2).toString(16));
    address = parts.join(":");
  } else {
    logger.debug(`Unknown address type: ${addrType}`);
    return { status: "invalid" };
  }

  return {
    status: "ok",
    command,
    port,
    address,
    payloadOffset: addressEndIndex,
  };
}

function isBlockedAddress(address: string): boolean {
  if (address === "localhost") {
    return true;
  }
  if (address === "::1") {
    return true;
  }
  if (address.startsWith("127.")) {
    return true;
  }
  if (isPrivateIpv4(address)) {
    return true;
  }
  if (isPrivateIpv6(address)) {
    return true;
  }
  return false;
}

async function resolveTargetAddress(
  address: string,
  dohUrl: string | null,
  logger: Logger,
  sessionState: SessionState,
): Promise<string | null> {
  if (address.includes(":") || /^\d+\.\d+\.\d+\.\d+$/.test(address)) {
    return address;
  }
  if (sessionState.resolveCount >= DNS_MAX_RESOLVES_PER_SESSION) {
    logger.warn("DNS resolve limit exceeded for session.");
    return null;
  }
  sessionState.resolveCount += 1;
  const cached = getDnsCache(address);
  if (cached !== undefined) {
    return cached;
  }
  if (dohUrl) {
    try {
      const records = await resolveDnsOverHttps(
        address,
        "A",
        dohUrl,
        DOH_TIMEOUT_MS,
      );
      if (records.length > 0) {
        setDnsCache(address, records[0]);
        return records[0];
      }
      const recordsV6 = await resolveDnsOverHttps(
        address,
        "AAAA",
        dohUrl,
        DOH_TIMEOUT_MS,
      );
      if (recordsV6.length > 0) {
        setDnsCache(address, recordsV6[0]);
        return recordsV6[0];
      }
    } catch (error) {
      logger.warn(`DoH resolve failed for ${maskIP(address)}`, error);
    }
  }
  try {
    const fallbackRecords = await withTimeout(
      Deno.resolveDns(address, "A"),
      DNS_FALLBACK_TIMEOUT_MS,
    );
    if (fallbackRecords.length > 0) {
      setDnsCache(address, fallbackRecords[0]);
      return fallbackRecords[0];
    }
    const fallbackRecordsV6 = await withTimeout(
      Deno.resolveDns(address, "AAAA"),
      DNS_FALLBACK_TIMEOUT_MS,
    );
    if (fallbackRecordsV6.length > 0) {
      setDnsCache(address, fallbackRecordsV6[0]);
      return fallbackRecordsV6[0];
    }
  } catch (error) {
    logger.warn(`DNS resolve failed for ${maskIP(address)}`, error);
  }
  setDnsCache(address, null);
  return null;
}

type DohResponse = {
  Answer?: Array<{ data: string; type: number }>;
  Status?: number;
};

function getDnsCache(hostname: string): string | null | undefined {
  const entry = dnsCache.get(hostname);
  if (!entry) {
    return undefined;
  }
  if (Date.now() > entry.expiresAt) {
    dnsCache.delete(hostname);
    return undefined;
  }
  dnsCache.delete(hostname);
  dnsCache.set(hostname, entry);
  return entry.value;
}

function setDnsCache(hostname: string, value: string | null) {
  if (dnsCache.size >= DNS_CACHE_MAX_ENTRIES) {
    const oldestKey = dnsCache.keys().next().value;
    if (oldestKey) {
      dnsCache.delete(oldestKey);
    }
  }
  dnsCache.set(hostname, {
    value,
    expiresAt: Date.now() + DNS_CACHE_TTL_MS,
  });
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error("Operation timed out"));
    }, timeoutMs);
    promise.then((value) => {
      clearTimeout(timer);
      resolve(value);
    }).catch((error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function resolveDnsOverHttps(
  hostname: string,
  recordType: "A" | "AAAA",
  dohUrl: string,
  timeoutMs: number,
): Promise<string[]> {
  const url = new URL(dohUrl);
  url.searchParams.set("name", hostname);
  url.searchParams.set("type", recordType);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const response = await fetch(url.toString(), {
    headers: {
      accept: "application/dns-json",
    },
    signal: controller.signal,
  }).finally(() => clearTimeout(timeout));
  if (!response.ok) {
    throw new Error(`DoH request failed with status ${response.status}`);
  }
  const data = (await response.json()) as DohResponse;
  if (!data.Answer || data.Answer.length === 0) {
    return [];
  }
  const typeValue = recordType === "A" ? 1 : 28;
  return data.Answer
    .filter((answer) => answer.type === typeValue)
    .map((answer) => answer.data);
}

function isPrivateIpv4(address: string): boolean {
  const parts = address.split(".");
  if (parts.length !== 4) {
    return false;
  }
  const octets = parts.map((part) => Number(part));
  if (octets.some((octet) => Number.isNaN(octet) || octet < 0 || octet > 255)) {
    return false;
  }
  const [a, b] = octets;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 0) return true;
  return false;
}

function isPrivateIpv6(address: string): boolean {
  const normalized = address.toLowerCase();
  return normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80") ||
    normalized === "::";
}

function createWebSocketReadableStream(
  ws: WebSocket,
  earlyData: ArrayBuffer | undefined,
  logger: Logger,
): ReadableStream<Uint8Array> {
  const queue: Uint8Array[] = [];
  let queuedBytes = 0;
  let controllerRef: ReadableStreamDefaultController<Uint8Array> | null = null;
  let pullResolve: (() => void) | null = null;

  let streamClosed = false;
  const pump = () => {
    if (!controllerRef) {
      return;
    }
    while (queue.length > 0) {
      const desired = controllerRef.desiredSize;
      if (desired !== null && desired <= 0) {
        break;
      }
      const chunk = queue.shift();
      if (!chunk) {
        break;
      }
      queuedBytes -= chunk.length;
      controllerRef.enqueue(chunk);
    }
  };

  const enqueueChunk = (chunk: Uint8Array) => {
    if (!controllerRef || streamClosed) {
      return;
    }
    if (queuedBytes + chunk.length > MAX_WS_QUEUE_BYTES) {
      logger.warn("WebSocket receive queue overflow, closing connection.");
      streamClosed = true;
      controllerRef.error(new Error("WebSocket receive queue overflow"));
      try { ws.close(); } catch (_) {}
      return;
    }
    queue.push(chunk);
    queuedBytes += chunk.length;
    pump();
    if (pullResolve && queue.length > 0) {
      pullResolve();
      pullResolve = null;
    }
  };

  return new ReadableStream<Uint8Array>({
    start(controller) {
      controllerRef = controller;
      ws.onmessage = (event) => {
        if (streamClosed) {
          return;
        }
        if (event.data instanceof ArrayBuffer) {
          enqueueChunk(new Uint8Array(event.data));
        }
      };
      ws.onclose = () => {
        if (streamClosed) {
          return;
        }
        streamClosed = true;
        try {
          controller.close();
        } catch (_) {}
      };
      ws.onerror = (e) => {
        if (streamClosed) {
          return;
        }
        streamClosed = true;
        controller.error(e);
      };

      if (earlyData) {
        enqueueChunk(new Uint8Array(earlyData));
      }
    },
    pull() {
      pump();
      if (queue.length === 0) {
        return new Promise<void>((resolve) => {
          pullResolve = resolve;
        });
      }
    },
    cancel() {
      if (!streamClosed) {
        streamClosed = true;
      }
      ws.close();
    },
  });
}

function filterRequestHeaders(headers: Headers): Headers {
  const filtered = new Headers();
  const connectionHeader = headers.get("connection");
  const connectionTokens = connectionHeader
    ? connectionHeader.split(",").map((value) => value.trim().toLowerCase())
    : [];
  for (const [key, value] of headers.entries()) {
    const lowerKey = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowerKey) || connectionTokens.includes(lowerKey)) {
      continue;
    }
    if (FORWARDED_HEADER_PREFIXES.some((prefix) => lowerKey.startsWith(prefix))) {
      continue;
    }
    if (REDACTED_REQUEST_HEADERS.has(lowerKey)) {
      continue;
    }
    filtered.set(key, value);
  }
  return filtered;
}

function limitRequestBody(
  body: ReadableStream<Uint8Array>,
  maxBytes: number,
): ReadableStream<Uint8Array> {
  let received = 0;
  return body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        received += chunk.length;
        if (received > maxBytes) {
          controller.error(new Error("Request body too large"));
          return;
        }
        controller.enqueue(chunk);
      },
    }),
  );
}

function filterResponseHeaders(headers: Headers): Headers {
  const filtered = new Headers();
  const connectionHeader = headers.get("connection");
  const connectionTokens = connectionHeader
    ? connectionHeader.split(",").map((value) => value.trim().toLowerCase())
    : [];
  for (const [key, value] of headers.entries()) {
    const lowerKey = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowerKey) || connectionTokens.includes(lowerKey)) {
      continue;
    }
    filtered.set(key, value);
  }
  return filtered;
}
