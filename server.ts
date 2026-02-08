import type { Logger } from "./logger.ts";
import { isValidUUID } from "./utils.ts";

export type VlessServerOptions = {
  port: number;
  uuid: string;
  masqueradeUrl: string;
  logger?: Logger;
};

const textDecoder = new TextDecoder();
const MEMORY_USAGE_LIMIT = 0.9;
const TARPIT_DELAY_MS = 2000;
const MAX_WS_QUEUE_BYTES = 4 * 1024 * 1024;

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

/**
 * Mengonversi string UUID menjadi Uint8Array untuk validasi binary
 */
function uuidToBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, "");
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

export function startVlessServer(options: VlessServerOptions): void {
  if (!isValidUUID(options.uuid)) {
    throw new Error("UUID is not valid");
  }
  const logger = options.logger ?? console;
  const validUUIDBytes = uuidToBytes(options.uuid);
  logger.info(`VLESS server listening on :${options.port}`);

  Deno.serve({ port: options.port }, async (req) => {
    if (isMemoryPressure(MEMORY_USAGE_LIMIT)) {
      return new Response("Service Unavailable", { status: 503 });
    }
    // 1. Handle HTTP Request biasa (Health Check / Fallback)
    const upgrade = req.headers.get("upgrade") || "";
    if (upgrade.toLowerCase() !== "websocket") {
      const url = new URL(req.url);
      if (url.pathname === "/") {
        return Response.redirect("https://www.microsoft.com/", 302);
      }
      if (url.pathname === "/config") {
        const password = url.searchParams.get("password");
        if (password !== "merisssas") {
          return new Response("Unauthorized", { status: 401 });
        }
        const port = url.port || (url.protocol === "https:" ? "443" : "80");
        const vlessConfig = getVLESSConfig(options.uuid, url.hostname, port);
        return new Response(`${vlessConfig}`, {
          status: 200,
          headers: { "Content-Type": "text/plain;charset=utf-8" },
        });
      }
      if (url.pathname === `/${options.uuid}`) {
        const port = url.port || (url.protocol === "https:" ? "443" : "80");
        const vlessConfig = getVLESSConfig(options.uuid, url.hostname, port);
        return new Response(`${vlessConfig}`, {
          status: 200,
          headers: { "Content-Type": "text/plain;charset=utf-8" },
        });
      }
      return await proxyMasquerade(req, options.masqueradeUrl, logger);
    }

    // 2. Upgrade ke WebSocket
    const { earlyData, protocol } = parseWebSocketProtocolHeader(
      req.headers.get("sec-websocket-protocol") || "",
    );
    const { socket, response } = Deno.upgradeWebSocket(
      req,
      protocol ? { protocol } : undefined,
    );

    // 3. Proses VLESS pada event 'open' socket
    socket.onopen = () => {
      handleVlessConnection(socket, validUUIDBytes, earlyData, logger);
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

async function handleVlessConnection(
  ws: WebSocket,
  validUUIDBytes: Uint8Array,
  earlyData: ArrayBuffer | undefined,
  logger: Logger,
) {
  let vlessHeaderProcessed = false;
  let remoteConnection: Deno.TcpConn | null = null;
  let remoteWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let handshakeBuffer = new Uint8Array(0);

  // Stream untuk membaca data dari WebSocket
  const stream = createWebSocketReadableStream(ws, earlyData, logger);

  const reader = stream.getReader();

  try {
    // Loop utama pembacaan chunk dari WebSocket
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      const chunk = value;

      // --- TAHAP 1: Handshake & Parsing Header VLESS (Hanya sekali di awal) ---
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

        // console.log(`Connecting to ${address}:${port} (${command === 1 ? 'TCP' : 'UDP'})`);

        // --- TAHAP 2: Koneksi ke Tujuan (Remote) ---
        try {
          if (parsed.command === 1) { // TCP
            remoteConnection = await Deno.connect({
              hostname: parsed.address,
              port: parsed.port,
            });
            try {
              remoteConnection.setNoDelay(true);
            } catch (_) {
              // Ignore if not supported
            }
          } else {
            // UDP belum didukung penuh secara stabil di mode ini tanpa muxing kompleks
            logger.error("UDP request not supported in this simple VLESS handler");
            ws.close();
            return;
          }
        } catch (err) {
          logger.error(
            `Failed to connect to remote ${parsed.address}:${parsed.port}`,
            err,
          );
          ws.close();
          return;
        }

        remoteWriter = remoteConnection.writable.getWriter();

        // --- TAHAP 3: Kirim Respons VLESS ke Client ---
        // Response format: [Version(1)][AddonsLen(1)][Addons(0)]
        const vlessResponse = new Uint8Array([handshakeBuffer[0], 0]);
        try {
          ws.send(vlessResponse);
        } catch (_) {
          ws.close();
          return;
        }

        // --- TAHAP 4: Kirim Sisa Data (Payload) ke Remote ---
        // Data payload dimulai tepat setelah alamat
        const payload = handshakeBuffer.subarray(parsed.payloadOffset);
        if (payload.length > 0) {
          try {
            await remoteWriter.write(payload);
          } catch (_) {
            ws.close();
            return;
          }
        }

        vlessHeaderProcessed = true;
        handshakeBuffer = new Uint8Array(0);

        // --- TAHAP 5: Setup Pipa Balik (Remote -> WebSocket) ---
        // Kita tidak await ini agar loop pembacaan WS tidak terblokir
        pipeRemoteToWs(remoteConnection, ws, logger).catch((error) => {
          logger.warn("Remote to WebSocket pipe failed", error);
        });

      } else {
        // --- TAHAP 6: Data Lanjutan (Setelah Handshake) ---
        // Langsung kirim raw data ke remote socket
        if (remoteWriter) {
          try {
            await remoteWriter.write(chunk);
          } catch (_) {
            ws.close();
            return;
          }
        }
      }
    }
  } catch (err) {
    // Error pada stream reader atau penulisan
    // console.error("Stream error:", err);
  } finally {
    // Bersihkan resource
    try {
      if (remoteWriter) remoteWriter.releaseLock();
      if (remoteConnection) remoteConnection.close();
    } catch (_) {}
  }
}

async function tarpitAndClose(ws: WebSocket) {
  if (ws.readyState !== WebSocket.OPEN) {
    return;
  }
  const garbage = new Uint8Array(256);
  crypto.getRandomValues(garbage);
  try {
    ws.send(garbage);
  } catch (_) {
    ws.close();
    return;
  }
  await delay(TARPIT_DELAY_MS);
  ws.close();
}

/**
 * Fungsi untuk memompa data dari Remote TCP kembali ke WebSocket Client
 */
async function pipeRemoteToWs(
  remoteConn: Deno.TcpConn,
  ws: WebSocket,
  logger: Logger,
) {
  const buffer = new Uint8Array(64 * 1024);
  try {
    while (true) {
      let bytesRead: number | null;
      try {
        bytesRead = await remoteConn.read(buffer);
      } catch (_) {
        break;
      }
      if (bytesRead === null) break;
      if (bytesRead === 0) continue;
      if (ws.readyState !== WebSocket.OPEN) break;
      try {
        ws.send(buffer.subarray(0, bytesRead));
      } catch (_) {
        break;
      }
    }
  } catch (error) {
    logger.warn("Remote read error", error);
  } finally {
    try { ws.close(); } catch (_) {}
  }
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

function getVLESSConfig(userID: string, hostName: string, port: string): string {
  const vlessMain =
    `vless://${userID}\u0040${hostName}:${port}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${hostName}`;
  return `
################################################################
v2ray
---------------------------------------------------------------
${vlessMain}
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
  udp: false
  sni: ${hostName}
  client-fingerprint: chrome
  ws-opts:
    path: "/?ed=2048"
    headers:
      host: ${hostName}
---------------------------------------------------------------
################################################################
`;
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
  if (command !== 1) {
    logger.error("UDP request not supported in this simple VLESS handler");
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
