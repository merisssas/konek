import {
  createErrorLogBuffer,
  createLogger,
  type ErrorLogBuffer,
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
  errorLogBuffer: ErrorLogBuffer;
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
const DEFAULT_LOG_LEVEL: LogLevel = "none";
const DEFAULT_VERBOSE_LOG_LEVEL: LogLevel = "debug";
const DEFAULT_STEALTH_MODE = true;
const DEFAULT_MASQUERADE_URL = "https://www.microsoft.com/";
const DEFAULT_SHADOWSOCKS_METHOD = "chacha20-ietf-poly1305";
const DEFAULT_SHADOWSOCKS_PASSWORD = "REPLACE_WITH_SHADOWSOCKS_PASSWORD";
const DEFAULT_SHADOWSOCKS_PORT = 8388;
const DEFAULT_TROJAN_PASSWORD = "REPLACE_WITH_TROJAN_PASSWORD";
const DEFAULT_TROJAN_PORT = 8443;

function isPlaceholder(value: string, placeholder: string): boolean {
  return value.trim() === "" || value === placeholder;
}

export async function loadConfig(): Promise<AppConfig> {
  const uuid = readEnv("UUID") ?? DEFAULT_UUID;
  const port = parsePort(readEnv("PORT"), DEFAULT_PORT);
  const stealthMode = parseBoolean(
    readEnv("STEALTH_MODE"),
    DEFAULT_STEALTH_MODE,
  );
  const logLevel = stealthMode
    ? DEFAULT_LOG_LEVEL
    : parseLogLevel(readEnv("LOG_LEVEL"), DEFAULT_VERBOSE_LOG_LEVEL);
  const masqueradeUrl = readEnv("MASQUERADE_URL") ?? DEFAULT_MASQUERADE_URL;

  const rawShadowsocksPassword = readEnv("SHADOWSOCKS_PASSWORD") ??
    DEFAULT_SHADOWSOCKS_PASSWORD;
  const shadowsocksPassword = isPlaceholder(
    rawShadowsocksPassword,
    DEFAULT_SHADOWSOCKS_PASSWORD,
  )
    ? uuid
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
    ? uuid
    : rawTrojanPassword;
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

  const errorLogBuffer = createErrorLogBuffer();
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
    stealthMode,
    masqueradeUrl,
    shadowsocks,
    trojan,
    protocolCommands,
    errorLogBuffer,
    logger,
  };
}
