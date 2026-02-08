import type { LogLevel } from "./logger.ts";

const VALID_LOG_LEVELS: LogLevel[] = ["none", "debug", "info", "warn", "error"];

export function readEnv(name: string): string | undefined {
  try {
    return Deno.env.get(name);
  } catch {
    return undefined;
  }
}

export function parsePort(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }

  const port = Number(value);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`PORT must be an integer between 1-65535. Received: ${value}`);
  }

  return port;
}

export function parseLogLevel(
  value: string | undefined,
  fallback: LogLevel,
): LogLevel {
  if (!value) {
    return fallback;
  }

  const normalized = value.toLowerCase();
  if (!VALID_LOG_LEVELS.includes(normalized as LogLevel)) {
    throw new Error(
      `LOG_LEVEL must be one of ${VALID_LOG_LEVELS.join(", ")}. Received: ${value}`,
    );
  }

  return normalized as LogLevel;
}

export function isValidUUID(uuid: string): boolean {
  const uuidRegex =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}
