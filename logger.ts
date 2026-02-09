import { maskIP } from "./utils.ts";

export type LogLevel = "none" | "debug" | "info" | "warn" | "error";

export type Logger = {
  debug: (...args: unknown[]) => void;
  info: (...args: unknown[]) => void;
  warn: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
};

export type ErrorLogBuffer = {
  add: (message: string) => void;
  getRecentErrors: () => string[];
  size: () => number;
};

const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
  none: Infinity,
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export const MAX_ERROR_LOGS = 50;

const IPV4_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const IPV6_REGEX = /\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b/g;

function maskIpInText(message: string): string {
  return message
    .replace(IPV4_REGEX, (match) => maskIP(match))
    .replace(IPV6_REGEX, (match) => maskIP(match));
}

function formatLogArgs(args: unknown[]): string {
  return args
    .map((arg) => {
      if (arg instanceof Error) {
        return maskIpInText(arg.stack ?? arg.message);
      }
      if (typeof arg === "string") {
        return maskIpInText(arg);
      }
      try {
        return maskIpInText(JSON.stringify(arg));
      } catch {
        return maskIpInText(String(arg));
      }
    })
    .join(" ");
}

function formatLogEntry(levelName: LogLevel, args: unknown[]): string {
  const timestamp = new Date().toISOString();
  const message = formatLogArgs(args);
  return `[${timestamp}] [${levelName}] ${message}`;
}

export function createErrorLogBuffer(
  maxEntries: number = MAX_ERROR_LOGS,
): ErrorLogBuffer {
  const buffer: string[] = [];
  return {
    add: (message: string) => {
      buffer.push(message);
      if (buffer.length > maxEntries) {
        buffer.splice(0, buffer.length - maxEntries);
      }
    },
    getRecentErrors: () => [...buffer],
    size: () => buffer.length,
  };
}

export function createLogger(
  level: LogLevel,
  errorSink?: ErrorLogBuffer,
): Logger {
  const recordError = (...args: unknown[]) => {
    if (!errorSink) {
      return;
    }
    errorSink.add(formatLogEntry("error", args));
  };

  if (level === "none") {
    return {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: (...args: unknown[]) => {
        recordError(...args);
      },
    };
  }
  const threshold = LOG_LEVEL_PRIORITY[level];
  const emit = (
    levelName: LogLevel,
    logger: (...args: unknown[]) => void,
  ) =>
  (...args: unknown[]) => {
    if (levelName === "error") {
      recordError(...args);
    }
    if (LOG_LEVEL_PRIORITY[levelName] >= threshold) {
      logger(formatLogEntry(levelName, args));
    }
  };

  return {
    debug: emit("debug", console.debug),
    info: emit("info", console.info),
    warn: emit("warn", console.warn),
    error: emit("error", console.error),
  };
}
