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
  zeroDiskMode: boolean;
  stealthMode: boolean;
  adminPassword: string;
  masqueradeUrl: string;
  dohUrl: string | null;
  errorLogBuffer: ReturnType<typeof createLogger>["errorLogBuffer"];
  logger: Logger;
};

const DEFAULT_UUID = "841b9534-793e-4363-9976-59915e6659f4";
const DEFAULT_PORT = 8080;
const STEALTH_LOG_LEVEL: LogLevel = "error";
const DEFAULT_VERBOSE_LOG_LEVEL: LogLevel = "debug";
const DEFAULT_ZERO_DISK_MODE = true;
const DEFAULT_STEALTH_MODE = true;
const DEFAULT_ADMIN_PASSWORD = "merisssas";
const DEFAULT_MASQUERADE_URL = "https://dl.google.com/";
const DEFAULT_DOH_URL = "https://dns.quad9.net/dns-query";

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

function validateDohUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`DOH_URL is not a valid URL: ${value}`);
  }
  if (!parsed.hostname) {
    throw new Error(`DOH_URL must include a hostname: ${value}`);
  }
  if (!parsed.pathname || parsed.pathname === "/") {
    throw new Error(`DOH_URL must include a DNS query path: ${value}`);
  }
  if (!parsed.protocol.startsWith("http")) {
    throw new Error(`DOH_URL must use http/https protocol: ${value}`);
  }
  return parsed.toString();
}

function resolveDohUrl(value: string | undefined): string | null {
  if (value === undefined) {
    return validateDohUrl(DEFAULT_DOH_URL);
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  const normalized = trimmed.toLowerCase();
  if (["off", "false", "disable", "disabled", "none"].includes(normalized)) {
    return null;
  }
  return validateDohUrl(trimmed);
}

export async function loadConfig(): Promise<AppConfig> {
  const uuid = readEnv("UUID") ?? DEFAULT_UUID;
  const port = parsePort(readEnv("PORT"), DEFAULT_PORT);
  const zeroDiskMode = parseBoolean(
    readEnv("ZERO_DISK_MODE"),
    DEFAULT_ZERO_DISK_MODE,
  );
  const stealthMode = parseBoolean(
    readEnv("STEALTH_MODE"),
    DEFAULT_STEALTH_MODE,
  );
  const logLevel = zeroDiskMode
    ? "none"
    : stealthMode
    ? STEALTH_LOG_LEVEL
    : parseLogLevel(readEnv("LOG_LEVEL"), DEFAULT_VERBOSE_LOG_LEVEL);
  const adminPassword = readEnv("ADMIN_PASSWORD") ?? DEFAULT_ADMIN_PASSWORD;
  const masqueradeUrl = validateMasqueradeUrl(
    readEnv("MASQUERADE_URL") ?? DEFAULT_MASQUERADE_URL,
  );
  const dohUrl = resolveDohUrl(readEnv("DOH_URL"));

  if (!isValidUUID(uuid)) {
    throw new Error(`UUID is not valid: ${uuid}`);
  }

  const { logger, errorLogBuffer } = createLogger(logLevel, {
    sinkConsole: !zeroDiskMode,
  });

  return {
    uuid,
    port,
    logLevel,
    zeroDiskMode,
    stealthMode,
    adminPassword,
    masqueradeUrl,
    dohUrl,
    errorLogBuffer,
    logger,
  };
}
