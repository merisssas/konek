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
  privateKey: string;
  publicKey: string;
  presharedKey: string;
  address: string;
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
const DEFAULT_WIREGUARD_PRESHARED_KEY = "REPLACE_WITH_WG_PRESHARED_KEY";
const DEFAULT_WIREGUARD_ADDRESS = "10.0.0.2/32";
const DEFAULT_WIREGUARD_DNS = "8.8.8.8";
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

function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function readServerDns(): Promise<string | null> {
  try {
    const content = await Deno.readTextFile("/etc/resolv.conf");
    const lines = content.split(/\r?\n/);
    for (const line of lines) {
      const match = line.match(/^\s*nameserver\s+(\S+)/);
      if (match?.[1]) {
        return match[1];
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
  const shouldGenerateWireguardKeys = isPlaceholder(
    rawWireguardPrivateKey,
    DEFAULT_WIREGUARD_PRIVATE_KEY,
  ) || isPlaceholder(rawWireguardPublicKey, DEFAULT_WIREGUARD_PUBLIC_KEY);
  const wireguardKeyPair = shouldGenerateWireguardKeys
    ? await generateX25519KeyPair()
    : {
      privateKey: rawWireguardPrivateKey,
      publicKey: rawWireguardPublicKey,
    };
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
    privateKey: wireguardKeyPair.privateKey,
    publicKey: wireguardKeyPair.publicKey,
    presharedKey: wireguardPresharedKey,
    address: readEnv("WIREGUARD_ADDRESS") ?? DEFAULT_WIREGUARD_ADDRESS,
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
