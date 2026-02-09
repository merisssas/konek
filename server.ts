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
  masqueradeUrl: string;
  shadowsocks: ShadowsocksConfig;
  trojan: TrojanConfig;
  protocolCommands: ProtocolCommandConfig;
  errorLogBuffer: ErrorLogBuffer;
  logger?: Logger;
};

const textDecoder = new TextDecoder();
const MEMORY_USAGE_LIMIT = 0.85;
const TARPIT_CONFIG = {
  minDelayMs: 1000,
  maxDelayMs: 4000,
  minBytes: 50,
  maxBytes: 300,
};
const MAX_WS_QUEUE_BYTES = 8 * 1024 * 1024;
const UDP_IDLE_TIMEOUT_MS = 15_000;
const UDP_IDLE_CHECK_INTERVAL_MS = 1_000;

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

export function startVlessServer(options: VlessServerOptions): void {
  const validUUIDBytes = uuidToBytes(options.uuid);
  if (!validUUIDBytes) {
    throw new Error("UUID is not valid");
  }
  const logger = options.logger ?? console;
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
    const { socket, response } = Deno.upgradeWebSocket(
      req,
      protocol ? { protocol } : undefined,
    );

    socket.onopen = () => {
      processVlessSession(socket, validUUIDBytes, earlyData, logger);
    };

    return response;
  });
}

function isMemoryPressure(limit: number): boolean {
  const info = Deno.systemMemoryInfo();
  if (info.total <= 0) {
    return false;
  }
  const available = info.available > 0 ? info.available : info.free;
  const usageRatio = (info.total - available) / info.total;
  return usageRatio >= limit;
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
    return new Response(formatErrorLogs(options.errorLogBuffer), {
      status: 200,
      headers: { "Content-Type": "text/plain;charset=utf-8" },
    });
  }
  if (url.pathname === "/info") {
    const password = url.searchParams.get("password");
    if (password !== "merisssas") {
      return new Response("Unauthorized", { status: 401 });
    }
    return new Response(formatServerInfo(options), {
      status: 200,
      headers: { "Content-Type": "application/json;charset=utf-8" },
    });
  }
  if (url.pathname === "/config") {
    const password = url.searchParams.get("password");
    if (password !== "merisssas") {
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
  const incomingUrl = new URL(req.url);
  const targetUrl = new URL(masqueradeUrl);
  targetUrl.pathname = incomingUrl.pathname;
  targetUrl.search = incomingUrl.search;

  const headers = filterRequestHeaders(req.headers);
  headers.set("host", targetUrl.host);

  const outboundRequest = new Request(targetUrl.toString(), {
    method: req.method,
    headers,
    body: req.body,
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
    logger.error("Masquerade proxy failed", error);
    return new Response("Service Unavailable", { status: 503 });
  }
}

async function processVlessSession(
  ws: WebSocket,
  validUUIDBytes: Uint8Array,
  earlyData: ArrayBuffer | undefined,
  logger: Logger,
) {
  let vlessHeaderProcessed = false;
  let handshakeBuffer = new Uint8Array(0);

  const wsStream = createWebSocketReadableStream(ws, earlyData, logger);
  const wsReader = wsStream.getReader();

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
          await tarpitAndClose(ws);
          return;
        }

        const resolvedTarget = await resolveTargetAddress(parsed.address, logger);
        if (!resolvedTarget || isBlockedAddress(resolvedTarget)) {
          const maskedAddress = maskIP(parsed.address);
          const maskedTarget = resolvedTarget ? maskIP(resolvedTarget) : "null";
          logger.warn(
            `Blocked or unresolved target: ${maskedAddress} -> ${maskedTarget}`,
          );
          ws.close();
          return;
        }

        const vlessResponse = new Uint8Array([handshakeBuffer[0], 0]);
        try {
          ws.send(vlessResponse);
        } catch (_) {
          ws.close();
          return;
        }

        vlessHeaderProcessed = true;
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
  }
}

async function handleTcpPipe(
  ws: WebSocket,
  inputStream: ReadableStream<Uint8Array>,
  address: string,
  port: number,
  logger: Logger,
) {
  let remoteConn: Deno.TcpConn;
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

  const wsWritable = new WritableStream<Uint8Array>({
    write(chunk) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(chunk);
      }
    },
    close() {
      try {
        ws.close();
      } catch (_) {}
    },
    abort() {
      try {
        ws.close();
      } catch (_) {}
    },
  });

  try {
    await Promise.all([
      remoteConn.readable.pipeTo(wsWritable).catch(() => {}),
      inputStream.pipeTo(remoteConn.writable).catch(() => {}),
    ]);
  } catch (_) {
    // ignore pipe errors
  } finally {
    try {
      remoteConn.close();
    } catch (_) {}
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
    hostname: "0.0.0.0",
  });
  let closed = false;
  let lastActivity = Date.now();

  const closeAll = () => {
    if (closed) {
      return;
    }
    closed = true;
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
    const udpWriter = new WritableStream<Uint8Array>({
      async write(chunk) {
        markActivity();
        await udpConn.send(chunk, { transport: "udp", hostname: address, port });
      },
    });
    try {
      await inputStream.pipeTo(udpWriter);
    } catch (error) {
      logger.warn("UDP send failed", error);
    }
  };

  const udpToWs = async () => {
    try {
      for await (const [data] of udpConn) {
        markActivity();
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(data);
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
  return new ReadableStream<Uint8Array>({
    async start(controller) {
      controller.enqueue(head);
      try {
        await bodyStream.pipeTo(
          new WritableStream<Uint8Array>({
            write(chunk) {
              controller.enqueue(chunk);
            },
            close() {
              controller.close();
            },
            abort(error) {
              controller.error(error);
            },
          }),
        );
      } catch (error) {
        controller.error(error);
      }
    },
  });
}

async function tarpitAndClose(ws: WebSocket) {
  if (ws.readyState !== WebSocket.OPEN) {
    return;
  }
  const garbageSize = Math.floor(
    Math.random() * (TARPIT_CONFIG.maxBytes - TARPIT_CONFIG.minBytes + 1),
  ) + TARPIT_CONFIG.minBytes;
  const garbage = new Uint8Array(garbageSize);
  crypto.getRandomValues(garbage);
  try {
    ws.send(garbage);
  } catch (_) {
    ws.close();
    return;
  }
  const randomDelay = Math.floor(
    Math.random() *
      (TARPIT_CONFIG.maxDelayMs - TARPIT_CONFIG.minDelayMs + 1),
  ) + TARPIT_CONFIG.minDelayMs;
  await delay(randomDelay);
  ws.close();
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
      logger.error("UUID mismatch");
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
    logger.error(`Unknown address type: ${addrType}`);
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
  logger: Logger,
): Promise<string | null> {
  if (address.includes(":") || /^\d+\.\d+\.\d+\.\d+$/.test(address)) {
    return address;
  }
  try {
    const records = await Deno.resolveDns(address, "A");
    if (records.length > 0) {
      return records[0];
    }
    const recordsV6 = await Deno.resolveDns(address, "AAAA");
    if (recordsV6.length > 0) {
      return recordsV6[0];
    }
  } catch (error) {
    logger.warn(`DNS resolve failed for ${maskIP(address)}`, error);
  }
  return null;
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
    filtered.set(key, value);
  }
  return filtered;
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
