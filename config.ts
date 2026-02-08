import { createLogger, type LogLevel, type Logger } from "./logger.ts";
import { isValidUUID, parseLogLevel, parsePort, readEnv } from "./utils.ts";

export type AppConfig = {
  uuid: string;
  port: number;
  logLevel: LogLevel;
  masqueradeUrl: string;
  logger: Logger;
};

const DEFAULT_UUID = "841b9534-793e-4363-9976-59915e6659f4";
const DEFAULT_PORT = 8080;
const DEFAULT_LOG_LEVEL: LogLevel = "info";
const DEFAULT_MASQUERADE_URL = "https://www.microsoft.com/";

export function loadConfig(): AppConfig {
  const uuid = readEnv("UUID") ?? DEFAULT_UUID;
  const port = parsePort(readEnv("PORT"), DEFAULT_PORT);
  const logLevel = parseLogLevel(readEnv("LOG_LEVEL"), DEFAULT_LOG_LEVEL);
  const masqueradeUrl = readEnv("MASQUERADE_URL") ?? DEFAULT_MASQUERADE_URL;

  if (!isValidUUID(uuid)) {
    throw new Error(`UUID is not valid: ${uuid}`);
  }

  const logger = createLogger(logLevel);

  try {
    new URL(masqueradeUrl);
  } catch {
    throw new Error(`MASQUERADE_URL is not a valid URL: ${masqueradeUrl}`);
  }

  return { uuid, port, logLevel, masqueradeUrl, logger };
}
