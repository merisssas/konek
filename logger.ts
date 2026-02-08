export type LogLevel = "debug" | "info" | "warn" | "error";

export type Logger = {
  debug: (...args: unknown[]) => void;
  info: (...args: unknown[]) => void;
  warn: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
};

const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export function createLogger(level: LogLevel): Logger {
  const threshold = LOG_LEVEL_PRIORITY[level];
  const emit = (
    levelName: LogLevel,
    logger: (...args: unknown[]) => void,
  ) =>
  (...args: unknown[]) => {
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
