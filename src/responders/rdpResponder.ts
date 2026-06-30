import { ResponderContext } from "./types.js";

export const rdpNegotiationResponse = Buffer.from([
  0x03, 0x00, 0x00, 0x13,
  0x0e, 0xd0, 0x00, 0x00,
  0x12, 0x34, 0x00, 0x02,
  0x00, 0x08, 0x00, 0x02,
  0x00, 0x00, 0x00,
]);

export function buildRdpResponse(action: string, context: ResponderContext) {
  if (action === "fake_error") {
    return [Buffer.from("Cookie: mstshash=ACCESS-DENIED\r\n", "utf8")];
  }

  return [rdpNegotiationResponse, Buffer.from(context.serviceMemory.banner, "utf8")];
}
