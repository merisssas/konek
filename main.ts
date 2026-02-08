import { startVlessServer } from "./server.ts";

const DEFAULT_UUID = "841b9534-793e-4363-9976-59915e6659f4";
const DEFAULT_PORT = 8080;

const uuid = Deno.env.get("UUID") || DEFAULT_UUID;
const port = Number(Deno.env.get("PORT")) || DEFAULT_PORT;

startVlessServer({ port, uuid });
