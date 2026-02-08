import { loadConfig } from "./config.ts";
import { startVlessServer } from "./server.ts";

const config = loadConfig();

startVlessServer({
  port: config.port,
  uuid: config.uuid,
  masqueradeUrl: config.masqueradeUrl,
  reality: config.reality,
  errorLogBuffer: config.errorLogBuffer,
  logger: config.logger,
});
