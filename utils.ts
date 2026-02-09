import type { LogLevel } from "./logger.ts";

const VALID_LOG_LEVELS: LogLevel[] = ["none", "debug", "info", "warn", "error"];
const TRUE_VALUES = new Set(["true", "1", "yes", "y", "on"]);
const FALSE_VALUES = new Set(["false", "0", "no", "n", "off"]);
const UUID_HYPHEN_POSITIONS = new Set([8, 13, 18, 23]);
const HEX_DIGITS = "0123456789abcdef";

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

export function parseBoolean(
  value: string | undefined,
  fallback: boolean,
): boolean {
  if (value === undefined) {
    return fallback;
  }

  const normalized = value.trim().toLowerCase();
  if (TRUE_VALUES.has(normalized)) {
    return true;
  }
  if (FALSE_VALUES.has(normalized)) {
    return false;
  }

  throw new Error(
    `Boolean value must be one of true/false/1/0/yes/no/on/off. Received: ${value}`,
  );
}

export function isValidUUID(uuid: string): boolean {
  return uuidToBytes(uuid) !== null;
}

function hexToNibble(code: number): number {
  if (code >= 48 && code <= 57) {
    return code - 48;
  }
  if (code >= 65 && code <= 70) {
    return code - 55;
  }
  if (code >= 97 && code <= 102) {
    return code - 87;
  }
  return -1;
}

export function uuidToBytes(uuid: string): Uint8Array | null {
  if (uuid.length !== 36 && uuid.length !== 32) {
    return null;
  }
  if (uuid.length === 36) {
    for (const position of UUID_HYPHEN_POSITIONS) {
      if (uuid[position] !== "-") {
        return null;
      }
    }
  }

  const bytes = new Uint8Array(16);
  let byteIndex = 0;
  let highNibble = -1;

  for (let i = 0; i < uuid.length; i++) {
    const code = uuid.charCodeAt(i);
    if (code === 45) {
      continue;
    }
    const nibble = hexToNibble(code);
    if (nibble < 0) {
      return null;
    }
    if (highNibble < 0) {
      highNibble = nibble;
      continue;
    }
    if (byteIndex >= bytes.length) {
      return null;
    }
    bytes[byteIndex++] = (highNibble << 4) | nibble;
    highNibble = -1;
  }

  if (byteIndex !== bytes.length || highNibble !== -1) {
    return null;
  }
  if ((bytes[6] >> 4) !== 4) {
    return null;
  }
  if ((bytes[8] & 0xc0) !== 0x80) {
    return null;
  }

  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  let output = "";
  for (const byte of bytes) {
    output += HEX_DIGITS[byte >> 4] + HEX_DIGITS[byte & 0x0f];
  }
  return output;
}

export function bytesToUuid(bytes: Uint8Array): string {
  if (bytes.length !== 16) {
    throw new Error("UUID byte array must be 16 bytes long.");
  }
  const hex = bytesToHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${
    hex.slice(16, 20)
  }-${hex.slice(20)}`;
}

export function maskIP(address: string): string {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(address)) {
    const [a, b, c] = address.split(".");
    return `${a}.${b}.${c}.0`;
  }
  if (address.includes(":")) {
    const segments = address.split(":");
    const visible = segments.slice(0, 4).filter((segment) => segment !== "");
    return `${visible.join(":")}::`;
  }
  return address;
}
