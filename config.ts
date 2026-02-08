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

export function loadConfig(): AppConfig {
  const uuid = readEnv("UUID") ?? DEFAULT_UUID;
  const port = parsePort(readEnv("PORT"), DEFAULT_PORT);
  const logLevel = parseLogLevel(readEnv("LOG_LEVEL"), DEFAULT_LOG_LEVEL);
  const masqueradeUrl = readEnv("MASQUERADE_URL") ?? DEFAULT_MASQUERADE_URL;
  const reality: RealityConfig = {
    serverName: readEnv("REALITY_SERVER_NAME") ?? DEFAULT_REALITY_SERVER_NAME,
    dest: readEnv("REALITY_DEST") ?? DEFAULT_REALITY_DEST,
    privateKey: readEnv("REALITY_PRIVATE_KEY") ?? DEFAULT_REALITY_PRIVATE_KEY,
    publicKey: readEnv("REALITY_PUBLIC_KEY") ?? DEFAULT_REALITY_PUBLIC_KEY,
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
