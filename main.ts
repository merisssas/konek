import { loadConfig } from "./config.ts";
import { startVlessServer } from "./server.ts";

const config = await loadConfig();

startVlessServer({
  port: config.port,
  uuid: config.uuid,
  masqueradeUrl: config.masqueradeUrl,
  dohUrl: config.dohUrl,
  shadowsocks: config.shadowsocks,
  trojan: config.trojan,
  protocolCommands: config.protocolCommands,
  errorLogBuffer: config.errorLogBuffer,
  logger: config.logger,
});
