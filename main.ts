import { loadConfig } from "./config.ts";
import type { Logger } from "./logger.ts";
import { startVlessServer } from "./server.ts";

const config = await loadConfig();

registerGlobalErrorHandlers(config.logger);

startVlessServer({
  port: config.port,
  uuid: config.uuid,
  adminPassword: config.adminPassword,
  masqueradeUrl: config.masqueradeUrl,
  dohUrl: config.dohUrl,
  shadowsocks: config.shadowsocks,
  trojan: config.trojan,
  protocolCommands: config.protocolCommands,
  errorLogBuffer: config.errorLogBuffer,
  logger: config.logger,
});

function registerGlobalErrorHandlers(logger: Logger): void {
  globalThis.addEventListener("error", (event) => {
    logger.error("Unhandled error", event.error ?? event.message);
    event.preventDefault();
  });

  globalThis.addEventListener("unhandledrejection", (event) => {
    logger.error("Unhandled promise rejection", event.reason);
    event.preventDefault();
  });
}
