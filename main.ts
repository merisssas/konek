import { loadConfig } from "./config.ts";
import { startVlessServer } from "./server.ts";

const config = await loadConfig();

startVlessServer({
  port: config.port,
  uuid: config.uuid,
  masqueradeUrl: config.masqueradeUrl,
  reality: config.reality,
  shadowsocks: config.shadowsocks,
  trojan: config.trojan,
  wireguard: config.wireguard,
  zuivpn: config.zuivpn,
  protocolCommands: config.protocolCommands,
  errorLogBuffer: config.errorLogBuffer,
  logger: config.logger,
});
