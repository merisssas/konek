import type { Logger } from "./logger.ts";
import { isValidUUID } from "./utils.ts";

export type VlessServerOptions = {
  port: number;
  uuid: string;
  logger?: Logger;
};

const textDecoder = new TextDecoder();

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
    // 1. Handle HTTP Request biasa (Health Check / Fallback)
    const upgrade = req.headers.get("upgrade") || "";
    if (upgrade.toLowerCase() !== "websocket") {
      const url = new URL(req.url);
      if (url.pathname === "/") {
        return new Response("Hello, world!");
      }
      if (url.pathname === `/${options.uuid}`) {
        const port = url.port || (url.protocol === "https:" ? "443" : "80");
        const vlessConfig = getVLESSConfig(options.uuid, url.hostname, port);
        return new Response(`${vlessConfig}`, {
          status: 200,
          headers: { "Content-Type": "text/plain;charset=utf-8" },
        });
      }
      return new Response("Not found", { status: 404 });
    }

    // 2. Upgrade ke WebSocket
    const { socket, response } = Deno.upgradeWebSocket(req);
    const earlyDataHeader = req.headers.get("sec-websocket-protocol") || "";

    // 3. Proses VLESS pada event 'open' socket
    socket.onopen = () => {
      handleVlessConnection(socket, validUUIDBytes, earlyDataHeader, logger);
    };

    return response;
  });
}

async function handleVlessConnection(
  ws: WebSocket,
  validUUIDBytes: Uint8Array,
  earlyDataHeader: string,
  logger: Logger,
) {
  let vlessHeaderProcessed = false;
  let remoteConnection: Deno.TcpConn | null = null;
  let remoteWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;

  // Stream untuk membaca data dari WebSocket
  const stream = new ReadableStream({
    start(controller) {
      ws.onmessage = (event) => {
        if (event.data instanceof ArrayBuffer) {
          controller.enqueue(new Uint8Array(event.data));
        }
      };
      ws.onclose = () => controller.close();
      ws.onerror = (e) => controller.error(e);

      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(new Uint8Array(earlyData));
      }
    },
    cancel() {
      ws.close();
    }
  });

  const reader = stream.getReader();

  try {
    // Loop utama pembacaan chunk dari WebSocket
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      const chunk = value;

      // --- TAHAP 1: Handshake & Parsing Header VLESS (Hanya sekali di awal) ---
      if (!vlessHeaderProcessed) {
        if (chunk.length < 17) {
          // Data terlalu pendek untuk validasi UUID
          ws.close();
          return;
        }

        // Validasi UUID (Bytes 1-17)
        // Header structure: [Version(1)][UUID(16)][AddonsLen(1)]...
        const clientUUID = chunk.slice(1, 17);
        let isMatch = true;
        for (let i = 0; i < 16; i++) {
          if (clientUUID[i] !== validUUIDBytes[i]) {
            isMatch = false;
            break;
          }
        }

        if (!isMatch) {
          logger.error("UUID mismatch");
          ws.close();
          return;
        }

        // Parse Metadata VLESS
        const addonsLen = chunk[17];
        // Skip addons (biasanya 0) + command byte (1 byte)
        // Index awal data perintah ada di 18 + addonsLen
        const commandIndex = 18 + addonsLen;
        const command = chunk[commandIndex]; // 0x01 = TCP, 0x02 = UDP

        // Port (2 bytes, Big Endian) dimulai setelah command
        const portIndex = commandIndex + 1;
        const port = (chunk[portIndex] << 8) | chunk[portIndex + 1];

        // Address Type (1 byte)
        const addrTypeIndex = portIndex + 2;
        const addrType = chunk[addrTypeIndex];

        // Parse Alamat Tujuan
        let address = "";
        let addressEndIndex = 0;

        if (addrType === 1) {
          // IPv4 (4 bytes)
          addressEndIndex = addrTypeIndex + 1 + 4;
          address = chunk.slice(addrTypeIndex + 1, addressEndIndex).join(".");
        } else if (addrType === 2) {
          // Domain Name (Variable length: 1 byte len + string)
          const domainLen = chunk[addrTypeIndex + 1];
          addressEndIndex = addrTypeIndex + 1 + 1 + domainLen;
          const domainBytes = chunk.slice(addrTypeIndex + 2, addressEndIndex);
          address = textDecoder.decode(domainBytes);
        } else if (addrType === 3) {
          // IPv6 (16 bytes) - simplified handling
          addressEndIndex = addrTypeIndex + 1 + 16;
          // Parsing IPv6 di JS agak panjang, untuk efisiensi kita anggap valid atau gunakan library jika perlu strict
          // Disini kita format sederhana untuk koneksi Deno
          const view = new DataView(chunk.buffer, chunk.byteOffset + addrTypeIndex + 1, 16);
          const parts = [];
          for (let i = 0; i < 8; i++) parts.push(view.getUint16(i * 2).toString(16));
          address = parts.join(":");
        } else {
          logger.error(`Unknown address type: ${addrType}`);
          ws.close();
          return;
        }

        // console.log(`Connecting to ${address}:${port} (${command === 1 ? 'TCP' : 'UDP'})`);

        // --- TAHAP 2: Koneksi ke Tujuan (Remote) ---
        try {
          if (command === 1) { // TCP
            remoteConnection = await Deno.connect({ hostname: address, port: port });
          } else {
            // UDP belum didukung penuh secara stabil di mode ini tanpa muxing kompleks
            logger.error("UDP request not supported in this simple VLESS handler");
            ws.close();
            return;
          }
        } catch (err) {
          logger.error(`Failed to connect to remote ${address}:${port}`, err);
          ws.close();
          return;
        }

        remoteWriter = remoteConnection.writable.getWriter();

        // --- TAHAP 3: Kirim Respons VLESS ke Client ---
        // Response format: [Version(1)][AddonsLen(1)][Addons(0)]
        const vlessResponse = new Uint8Array([chunk[0], 0]);
        ws.send(vlessResponse);

        // --- TAHAP 4: Kirim Sisa Data (Payload) ke Remote ---
        // Data payload dimulai tepat setelah alamat
        const payload = chunk.slice(addressEndIndex);
        if (payload.length > 0) {
          await remoteWriter.write(payload);
        }

        vlessHeaderProcessed = true;

        // --- TAHAP 5: Setup Pipa Balik (Remote -> WebSocket) ---
        // Kita tidak await ini agar loop pembacaan WS tidak terblokir
        pipeRemoteToWs(remoteConnection, ws).catch(() => {});

      } else {
        // --- TAHAP 6: Data Lanjutan (Setelah Handshake) ---
        // Langsung kirim raw data ke remote socket
        if (remoteWriter) {
          await remoteWriter.write(chunk);
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

/**
 * Fungsi untuk memompa data dari Remote TCP kembali ke WebSocket Client
 */
async function pipeRemoteToWs(remoteConn: Deno.TcpConn, ws: WebSocket) {
  const reader = remoteConn.readable.getReader();
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(value);
      } else {
        break;
      }
    }
  } catch (err) {
    // console.error("Remote read error:", err);
  } finally {
    try { ws.close(); } catch (_) {}
  }
}

function base64ToArrayBuffer(base64Str: string): { earlyData?: ArrayBuffer; error?: Error } {
  if (!base64Str) {
    return { error: undefined };
  }
  try {
    const normalized = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = atob(normalized);
    const bytes = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
    return { earlyData: bytes.buffer };
  } catch (error) {
    return { error: error as Error };
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
