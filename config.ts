import { createLogger, type LogLevel, type Logger } from "./logger.ts";
import { isValidUUID, parseLogLevel, parsePort, readEnv } from "./utils.ts";

export type AppConfig = {
  uuid: string;
  port: number;
  logLevel: LogLevel;
  masqueradeUrl: string;
  reality: RealityConfig;
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

type RealityKeyPair = {
  privateKey: string;
  publicKey: string;
};

function isPlaceholder(value: string, placeholder: string): boolean {
  return value.trim() === "" || value === placeholder;
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
    : { privateKey: realityPrivateKey, publicKey: realityPublicKey };
  const reality: RealityConfig = {
    serverName: readEnv("REALITY_SERVER_NAME") ?? DEFAULT_REALITY_SERVER_NAME,
    dest: readEnv("REALITY_DEST") ?? DEFAULT_REALITY_DEST,
    privateKey: realityKeyPair.privateKey,
    publicKey: realityKeyPair.publicKey,
    shortId: readEnv("REALITY_SHORT_ID") ?? DEFAULT_REALITY_SHORT_ID,
    fingerprint: readEnv("REALITY_FINGERPRINT") ?? DEFAULT_REALITY_FINGERPRINT,
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

  return { uuid, port, logLevel, masqueradeUrl, reality, errorLogBuffer, logger };
}
