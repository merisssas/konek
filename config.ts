import { createLogger, type LogLevel, type Logger } from "./logger.ts";
import { isValidUUID, parseLogLevel, parsePort, readEnv } from "./utils.ts";

export type AppConfig = {
  uuid: string;
  port: number;
  logLevel: LogLevel;
  masqueradeUrl: string;
  reality: RealityConfig;
  shadowsocks: ShadowsocksConfig;
  trojan: TrojanConfig;
  wireguard: WireguardConfig;
  zuivpn: ZuiVpnConfig;
  protocolCommands: ProtocolCommandConfig;
  errorLogBuffer: string[];
  logger: Logger;
};

export type RealityConfig = {
  serverName: string;
  dest: string;
  privateKey: string;
  publicKey: string;
  shortId: string;
  fingerprint: string;
};

export type ShadowsocksConfig = {
  method: string;
  password: string;
  port: number;
};

export type TrojanConfig = {
  password: string;
  port: number;
};

export type WireguardConfig = {
  clientPrivateKey: string;
  clientPublicKey: string;
  serverPrivateKey: string;
  serverPublicKey: string;
  presharedKey: string;
  clientAddress: string;
  serverAddress: string;
  dns: string;
  port: number;
};

export type ZuiVpnConfig = {
  username: string;
  password: string;
  port: number;
};

export type ProtocolCommandConfig = {
  shadowsocks?: string;
  trojan?: string;
  wireguard?: string;
  zuivpn?: string;
};

const DEFAULT_UUID = "841b9534-793e-4363-9976-59915e6659f4";
const DEFAULT_PORT = 8080;
const DEFAULT_LOG_LEVEL: LogLevel = "none";
const DEFAULT_MASQUERADE_URL = "https://www.microsoft.com/";
const DEFAULT_REALITY_SERVER_NAME = "www.cloudflare.com";
const DEFAULT_REALITY_DEST = "www.cloudflare.com:443";
const DEFAULT_REALITY_PRIVATE_KEY = "REPLACE_WITH_PRIVATE_KEY";
const DEFAULT_REALITY_PUBLIC_KEY = "REPLACE_WITH_PUBLIC_KEY";
const DEFAULT_REALITY_SHORT_ID = "a1b2c3d4";
const DEFAULT_REALITY_FINGERPRINT = "chrome";
const DEFAULT_SHADOWSOCKS_METHOD = "chacha20-ietf-poly1305";
const DEFAULT_SHADOWSOCKS_PASSWORD = "REPLACE_WITH_SHADOWSOCKS_PASSWORD";
const DEFAULT_SHADOWSOCKS_PORT = 8388;
const DEFAULT_TROJAN_PASSWORD = "REPLACE_WITH_TROJAN_PASSWORD";
const DEFAULT_TROJAN_PORT = 443;
const DEFAULT_WIREGUARD_PRIVATE_KEY = "REPLACE_WITH_WG_PRIVATE_KEY";
const DEFAULT_WIREGUARD_PUBLIC_KEY = "REPLACE_WITH_WG_PUBLIC_KEY";
const DEFAULT_WIREGUARD_SERVER_PRIVATE_KEY =
  "REPLACE_WITH_WG_SERVER_PRIVATE_KEY";
const DEFAULT_WIREGUARD_SERVER_PUBLIC_KEY = "REPLACE_WITH_WG_SERVER_PUBLIC_KEY";
const DEFAULT_WIREGUARD_PRESHARED_KEY = "REPLACE_WITH_WG_PRESHARED_KEY";
const DEFAULT_WIREGUARD_ADDRESS = "10.0.0.2/32";
const DEFAULT_WIREGUARD_SERVER_ADDRESS = "10.0.0.1/24";
const DEFAULT_WIREGUARD_DNS = "1.1.1.1,8.8.8.8";
const DEFAULT_WIREGUARD_PORT = 51820;
const DEFAULT_ZUIVPN_USERNAME = "REPLACE_WITH_ZUIVPN_USERNAME";
const DEFAULT_ZUIVPN_PASSWORD = "REPLACE_WITH_ZUIVPN_PASSWORD";
const DEFAULT_ZUIVPN_PORT = 1194;

type RealityKeyPair = {
  privateKey: string;
  publicKey: string;
};

type KeyPair = {
  privateKey: string;
  publicKey: string;
};

function isPlaceholder(value: string, placeholder: string): boolean {
  return value.trim() === "" || value === placeholder;
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function base64Decode(value: string): Uint8Array | null {
  if (!value) {
    return null;
  }
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function parseIpv4(candidate: string): number[] | null {
  const parts = candidate.split(".");
  if (parts.length !== 4) {
    return null;
  }
  const bytes = parts.map((part) => Number(part));
  if (bytes.some((byte) => Number.isNaN(byte) || byte < 0 || byte > 255)) {
    return null;
  }
  return bytes;
}

function isPrivateIpv4(bytes: number[]): boolean {
  const [a, b] = bytes;
  if (a === 10) {
    return true;
  }
  if (a === 172 && b >= 16 && b <= 31) {
    return true;
  }
  if (a === 192 && b === 168) {
    return true;
  }
  return false;
}

function isReservedIpv4(bytes: number[]): boolean {
  const [a, b] = bytes;
  if (a === 0 || a === 127) {
    return true;
  }
  if (a === 169 && b === 254) {
    return true;
  }
  if (a === 100 && b >= 64 && b <= 127) {
    return true;
  }
  return false;
}

function isLocalIpv6(candidate: string): boolean {
  const value = candidate.toLowerCase();
  if (value === "::1") {
    return true;
  }
  if (value.startsWith("fe80:")) {
    return true;
  }
  if (value.startsWith("fc") || value.startsWith("fd")) {
    return true;
  }
  return false;
}

function isUsableDns(candidate: string): boolean {
  const ipv4 = parseIpv4(candidate);
  if (ipv4) {
    return !isPrivateIpv4(ipv4) && !isReservedIpv4(ipv4);
  }
  if (candidate.includes(":")) {
    return !isLocalIpv6(candidate);
  }
  return false;
}

async function readServerDns(): Promise<string | null> {
  try {
    const content = await Deno.readTextFile("/etc/resolv.conf");
    const lines = content.split(/\r?\n/);
    for (const line of lines) {
      const match = line.match(/^\s*nameserver\s+(\S+)/);
      if (match?.[1]) {
        const candidate = match[1].trim();
        if (!candidate) {
          continue;
        }
        if (!isUsableDns(candidate)) {
          continue;
        }
        return candidate;
      }
    }
  } catch {
    return null;
  }
  return null;
}

function normalizeRealityPublicKey(value: string): string {
  return value.trim().replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function generateToken(length: number): string {
  return base64UrlEncode(randomBytes(length));
}

async function generateRealityKeyPair(): Promise<RealityKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "X25519", namedCurve: "X25519" },
    true,
    ["deriveBits"],
  );
  const publicRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey),
  );
  const privatePkcs8 = new Uint8Array(
    await crypto.subtle.exportKey("pkcs8", keyPair.privateKey),
  );
  const privateRaw = privatePkcs8.slice(-32);
  return {
    publicKey: base64UrlEncode(publicRaw),
    privateKey: base64Encode(privateRaw),
  };
}

async function generateX25519KeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "X25519", namedCurve: "X25519" },
    true,
    ["deriveBits"],
  );
  const publicRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey),
  );
  const privatePkcs8 = new Uint8Array(
    await crypto.subtle.exportKey("pkcs8", keyPair.privateKey),
  );
  const privateRaw = privatePkcs8.slice(-32);
  return {
    publicKey: base64Encode(publicRaw),
    privateKey: base64Encode(privateRaw),
  };
}

async function deriveX25519PublicKey(
  privateKeyBase64: string,
): Promise<string | null> {
  const rawPrivateKey = base64Decode(privateKeyBase64);
  if (!rawPrivateKey || rawPrivateKey.length !== 32) {
    return null;
  }
  const pkcs8Prefix = Uint8Array.from([
    0x30,
    0x2e,
    0x02,
    0x01,
    0x00,
    0x30,
    0x05,
    0x06,
    0x03,
    0x2b,
    0x65,
    0x6e,
    0x04,
    0x22,
    0x04,
    0x20,
  ]);
  const pkcs8Key = new Uint8Array(pkcs8Prefix.length + rawPrivateKey.length);
  pkcs8Key.set(pkcs8Prefix);
  pkcs8Key.set(rawPrivateKey, pkcs8Prefix.length);

  try {
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      pkcs8Key,
      { name: "X25519", namedCurve: "X25519" },
      true,
      ["deriveBits"],
    );
    const basepoint = new Uint8Array(32);
    basepoint[0] = 9;
    const publicKey = await crypto.subtle.importKey(
      "raw",
      basepoint,
      { name: "X25519", namedCurve: "X25519" },
      true,
      [],
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "X25519", public: publicKey },
      privateKey,
      256,
    );
    return base64Encode(new Uint8Array(bits));
  } catch {
    return null;
  }
}

export async function loadConfig(): Promise<AppConfig> {
  const uuid = readEnv("UUID") ?? DEFAULT_UUID;
  const port = parsePort(readEnv("PORT"), DEFAULT_PORT);
  const logLevel = parseLogLevel(readEnv("LOG_LEVEL"), DEFAULT_LOG_LEVEL);
  const masqueradeUrl = readEnv("MASQUERADE_URL") ?? DEFAULT_MASQUERADE_URL;
  const realityPrivateKey = readEnv("REALITY_PRIVATE_KEY") ??
    DEFAULT_REALITY_PRIVATE_KEY;
  const realityPublicKey = readEnv("REALITY_PUBLIC_KEY") ??
    DEFAULT_REALITY_PUBLIC_KEY;
  const shouldGenerateRealityKeys = isPlaceholder(
    realityPrivateKey,
    DEFAULT_REALITY_PRIVATE_KEY,
  ) || isPlaceholder(realityPublicKey, DEFAULT_REALITY_PUBLIC_KEY);
  const realityKeyPair = shouldGenerateRealityKeys
    ? await generateRealityKeyPair()
    : {
      privateKey: realityPrivateKey,
      publicKey: normalizeRealityPublicKey(realityPublicKey),
    };
  const reality: RealityConfig = {
    serverName: readEnv("REALITY_SERVER_NAME") ?? DEFAULT_REALITY_SERVER_NAME,
    dest: readEnv("REALITY_DEST") ?? DEFAULT_REALITY_DEST,
    privateKey: realityKeyPair.privateKey,
    publicKey: realityKeyPair.publicKey,
    shortId: readEnv("REALITY_SHORT_ID") ?? DEFAULT_REALITY_SHORT_ID,
    fingerprint: readEnv("REALITY_FINGERPRINT") ?? DEFAULT_REALITY_FINGERPRINT,
  };

  const rawShadowsocksPassword = readEnv("SHADOWSOCKS_PASSWORD") ??
    DEFAULT_SHADOWSOCKS_PASSWORD;
  const shadowsocksPassword = isPlaceholder(
    rawShadowsocksPassword,
    DEFAULT_SHADOWSOCKS_PASSWORD,
  )
    ? generateToken(32)
    : rawShadowsocksPassword;
  const shadowsocks: ShadowsocksConfig = {
    method: readEnv("SHADOWSOCKS_METHOD") ?? DEFAULT_SHADOWSOCKS_METHOD,
    password: shadowsocksPassword,
    port: parsePort(readEnv("SHADOWSOCKS_PORT"), DEFAULT_SHADOWSOCKS_PORT),
  };

  const rawTrojanPassword = readEnv("TROJAN_PASSWORD") ?? DEFAULT_TROJAN_PASSWORD;
  const trojanPassword = isPlaceholder(
    rawTrojanPassword,
    DEFAULT_TROJAN_PASSWORD,
  )
    ? generateToken(32)
    : rawTrojanPassword;
  const trojan: TrojanConfig = {
    password: trojanPassword,
    port: parsePort(readEnv("TROJAN_PORT"), DEFAULT_TROJAN_PORT),
  };

  const rawWireguardPrivateKey = readEnv("WIREGUARD_PRIVATE_KEY") ??
    DEFAULT_WIREGUARD_PRIVATE_KEY;
  const rawWireguardPublicKey = readEnv("WIREGUARD_PUBLIC_KEY") ??
    DEFAULT_WIREGUARD_PUBLIC_KEY;
  let wireguardKeyPair: KeyPair | null = null;
  const hasWireguardPrivateKey = !isPlaceholder(
    rawWireguardPrivateKey,
    DEFAULT_WIREGUARD_PRIVATE_KEY,
  );
  const hasWireguardPublicKey = !isPlaceholder(
    rawWireguardPublicKey,
    DEFAULT_WIREGUARD_PUBLIC_KEY,
  );
  if (hasWireguardPrivateKey) {
    if (hasWireguardPublicKey) {
      wireguardKeyPair = {
        privateKey: rawWireguardPrivateKey,
        publicKey: rawWireguardPublicKey,
      };
    } else {
      const derivedPublicKey = await deriveX25519PublicKey(
        rawWireguardPrivateKey,
      );
      wireguardKeyPair = derivedPublicKey
        ? { privateKey: rawWireguardPrivateKey, publicKey: derivedPublicKey }
        : null;
    }
  }
  if (!wireguardKeyPair) {
    wireguardKeyPair = await generateX25519KeyPair();
  }
  const rawWireguardServerPrivateKey = readEnv("WIREGUARD_SERVER_PRIVATE_KEY") ??
    DEFAULT_WIREGUARD_SERVER_PRIVATE_KEY;
  const rawWireguardServerPublicKey = readEnv("WIREGUARD_SERVER_PUBLIC_KEY") ??
    DEFAULT_WIREGUARD_SERVER_PUBLIC_KEY;
  let wireguardServerKeyPair: KeyPair | null = null;
  const hasWireguardServerPrivateKey = !isPlaceholder(
    rawWireguardServerPrivateKey,
    DEFAULT_WIREGUARD_SERVER_PRIVATE_KEY,
  );
  const hasWireguardServerPublicKey = !isPlaceholder(
    rawWireguardServerPublicKey,
    DEFAULT_WIREGUARD_SERVER_PUBLIC_KEY,
  );
  if (hasWireguardServerPrivateKey) {
    if (hasWireguardServerPublicKey) {
      wireguardServerKeyPair = {
        privateKey: rawWireguardServerPrivateKey,
        publicKey: rawWireguardServerPublicKey,
      };
    } else {
      const derivedPublicKey = await deriveX25519PublicKey(
        rawWireguardServerPrivateKey,
      );
      wireguardServerKeyPair = derivedPublicKey
        ? {
          privateKey: rawWireguardServerPrivateKey,
          publicKey: derivedPublicKey,
        }
        : null;
    }
  }
  if (!wireguardServerKeyPair) {
    wireguardServerKeyPair = await generateX25519KeyPair();
  }
  const rawWireguardPresharedKey = readEnv("WIREGUARD_PRESHARED_KEY") ??
    DEFAULT_WIREGUARD_PRESHARED_KEY;
  const wireguardPresharedKey = isPlaceholder(
    rawWireguardPresharedKey,
    DEFAULT_WIREGUARD_PRESHARED_KEY,
  )
    ? base64Encode(randomBytes(32))
    : rawWireguardPresharedKey;
  const serverDns = await readServerDns();
  const wireguard: WireguardConfig = {
    clientPrivateKey: wireguardKeyPair.privateKey,
    clientPublicKey: wireguardKeyPair.publicKey,
    serverPrivateKey: wireguardServerKeyPair.privateKey,
    serverPublicKey: wireguardServerKeyPair.publicKey,
    presharedKey: wireguardPresharedKey,
    clientAddress: readEnv("WIREGUARD_ADDRESS") ?? DEFAULT_WIREGUARD_ADDRESS,
    serverAddress: readEnv("WIREGUARD_SERVER_ADDRESS") ??
      DEFAULT_WIREGUARD_SERVER_ADDRESS,
    dns: readEnv("WIREGUARD_DNS") ?? serverDns ?? DEFAULT_WIREGUARD_DNS,
    port: parsePort(readEnv("WIREGUARD_PORT"), DEFAULT_WIREGUARD_PORT),
  };

  const rawZuivpnUsername = readEnv("ZUIVPN_USERNAME") ??
    DEFAULT_ZUIVPN_USERNAME;
  const rawZuivpnPassword = readEnv("ZUIVPN_PASSWORD") ??
    DEFAULT_ZUIVPN_PASSWORD;
  const zuivpnUsername = isPlaceholder(
    rawZuivpnUsername,
    DEFAULT_ZUIVPN_USERNAME,
  )
    ? `zuivpn-${generateToken(6)}`
    : rawZuivpnUsername;
  const zuivpnPassword = isPlaceholder(
    rawZuivpnPassword,
    DEFAULT_ZUIVPN_PASSWORD,
  )
    ? generateToken(12)
    : rawZuivpnPassword;
  const zuivpn: ZuiVpnConfig = {
    username: zuivpnUsername,
    password: zuivpnPassword,
    port: parsePort(readEnv("ZUIVPN_PORT"), DEFAULT_ZUIVPN_PORT),
  };
  const protocolCommands: ProtocolCommandConfig = {
    shadowsocks: readEnv("SHADOWSOCKS_COMMAND"),
    trojan: readEnv("TROJAN_COMMAND"),
    wireguard: readEnv("WIREGUARD_COMMAND"),
    zuivpn: readEnv("ZUIVPN_COMMAND"),
  };

  if (!isValidUUID(uuid)) {
    throw new Error(`UUID is not valid: ${uuid}`);
  }

  const errorLogBuffer: string[] = [];
  const logger = createLogger(logLevel, errorLogBuffer);

  try {
    new URL(masqueradeUrl);
  } catch {
    throw new Error(`MASQUERADE_URL is not a valid URL: ${masqueradeUrl}`);
  }

  return {
    uuid,
    port,
    logLevel,
    masqueradeUrl,
    reality,
    shadowsocks,
    trojan,
    wireguard,
    zuivpn,
    protocolCommands,
    errorLogBuffer,
    logger,
  };
}
