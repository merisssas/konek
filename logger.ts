export type LogLevel = "none" | "debug" | "info" | "warn" | "error";

export type Logger = {
  debug: (...args: unknown[]) => void;
  info: (...args: unknown[]) => void;
  warn: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
};

const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
  none: Infinity,
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

function formatLogArgs(args: unknown[]): string {
  return args
    .map((arg) => {
      if (arg instanceof Error) {
        return arg.stack ?? arg.message;
      }
      if (typeof arg === "string") {
        return arg;
      }
      try {
        return JSON.stringify(arg);
      } catch {
        return String(arg);
      }
    })
    .join(" ");
}

export function createLogger(level: LogLevel, errorSink?: string[]): Logger {
  const recordError = (...args: unknown[]) => {
    if (!errorSink) {
      return;
    }
    const timestamp = new Date().toISOString();
    errorSink.push(`[${timestamp}] ${formatLogArgs(args)}`);
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
      logger(`[${levelName}]`, ...args);
    }
  };

  return {
    debug: emit("debug", console.debug),
    info: emit("info", console.info),
    warn: emit("warn", console.warn),
    error: emit("error", console.error),
  };
}
