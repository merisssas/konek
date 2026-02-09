import {
  createLogger,
  type LogLevel,
  type Logger,
} from "./logger.ts";
import {
  isValidUUID,
  parseBoolean,
  parseLogLevel,
  parsePort,
  readEnv,
} from "./utils.ts";

export type AppConfig = {
  uuid: string;
  port: number;
  logLevel: LogLevel;
  stealthMode: boolean;
  masqueradeUrl: string;
  shadowsocks: ShadowsocksConfig;
  trojan: TrojanConfig;
  protocolCommands: ProtocolCommandConfig;
  errorLogBuffer: ReturnType<typeof createLogger>["errorLogBuffer"];
  logger: Logger;
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

export type ProtocolCommandConfig = {
  shadowsocks?: string;
  trojan?: string;
};

const DEFAULT_UUID = "841b9534-793e-4363-9976-59915e6659f4";
const DEFAULT_PORT = 8080;
const STEALTH_LOG_LEVEL: LogLevel = "error";
const DEFAULT_VERBOSE_LOG_LEVEL: LogLevel = "debug";
const DEFAULT_STEALTH_MODE = true;
const DEFAULT_MASQUERADE_URL = "https://dl.google.com/";
const DEFAULT_SHADOWSOCKS_METHOD = "chacha20-ietf-poly1305";
const DEFAULT_SHADOWSOCKS_PASSWORD = "REPLACE_WITH_SHADOWSOCKS_PASSWORD";
const DEFAULT_SHADOWSOCKS_PORT = 8388;
const DEFAULT_TROJAN_PASSWORD = "REPLACE_WITH_TROJAN_PASSWORD";
const DEFAULT_TROJAN_PORT = 8443;

function isPlaceholder(value: string, placeholder: string): boolean {
  return value.trim() === "" || value === placeholder;
}

function resolvePassword(
  value: string,
  placeholder: string,
  fallback: string,
): string {
  return isPlaceholder(value, placeholder) ? fallback : value;
}

function validateMasqueradeUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`MASQUERADE_URL is not a valid URL: ${value}`);
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(
      `MASQUERADE_URL must use http/https protocol: ${value}`,
    );
  }
  if (!parsed.hostname) {
    throw new Error(`MASQUERADE_URL must include a hostname: ${value}`);
  }
  return parsed.toString();
}

export async function loadConfig(): Promise<AppConfig> {
  const uuid = readEnv("UUID") ?? DEFAULT_UUID;
  const port = parsePort(readEnv("PORT"), DEFAULT_PORT);
  const stealthMode = parseBoolean(
    readEnv("STEALTH_MODE"),
    DEFAULT_STEALTH_MODE,
  );
  const logLevel = stealthMode
    ? STEALTH_LOG_LEVEL
    : parseLogLevel(readEnv("LOG_LEVEL"), DEFAULT_VERBOSE_LOG_LEVEL);
  const masqueradeUrl = validateMasqueradeUrl(
    readEnv("MASQUERADE_URL") ?? DEFAULT_MASQUERADE_URL,
  );

  const rawShadowsocksPassword = readEnv("SHADOWSOCKS_PASSWORD") ??
    DEFAULT_SHADOWSOCKS_PASSWORD;
  const shadowsocksPassword = resolvePassword(
    rawShadowsocksPassword,
    DEFAULT_SHADOWSOCKS_PASSWORD,
    uuid,
  );
  const shadowsocks: ShadowsocksConfig = {
    method: readEnv("SHADOWSOCKS_METHOD") ?? DEFAULT_SHADOWSOCKS_METHOD,
    password: shadowsocksPassword,
    port: parsePort(readEnv("SHADOWSOCKS_PORT"), DEFAULT_SHADOWSOCKS_PORT),
  };

  const rawTrojanPassword = readEnv("TROJAN_PASSWORD") ?? DEFAULT_TROJAN_PASSWORD;
  const trojanPassword = resolvePassword(
    rawTrojanPassword,
    DEFAULT_TROJAN_PASSWORD,
    uuid,
  );
  const trojan: TrojanConfig = {
    password: trojanPassword,
    port: parsePort(readEnv("TROJAN_PORT"), DEFAULT_TROJAN_PORT),
  };
  const protocolCommands: ProtocolCommandConfig = {
    shadowsocks: readEnv("SHADOWSOCKS_COMMAND"),
    trojan: readEnv("TROJAN_COMMAND"),
  };

  if (!isValidUUID(uuid)) {
    throw new Error(`UUID is not valid: ${uuid}`);
  }

  const { logger, errorLogBuffer } = createLogger(logLevel);

  return {
    uuid,
    port,
    logLevel,
    stealthMode,
    masqueradeUrl,
    shadowsocks,
    trojan,
    protocolCommands,
    errorLogBuffer,
    logger,
  };
}
