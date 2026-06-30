import { pickDeterministic } from "./common.js";
import { sanitizeText } from "./safety.js";
import { ResponderContext } from "./types.js";

export function buildPostgresReply(payload: string, action: string, context: ResponderContext) {
  if (action === "fake_error") {
    return `FATAL: connection to ${context.serviceMemory.host} terminated by administrator command`;
  }

  if (/copy\s+/i.test(payload)) {
    return "ERROR: must be superuser to COPY to or from a file";
  }

  if (/union\s+select/i.test(payload) || /or\s+1=1/i.test(payload)) {
    return "ERROR: syntax error at or near \"UNION\"";
  }

  if (/select/i.test(payload)) {
    return pickDeterministic(`${context.attacker.id}:${payload}`, [
      "ERROR: permission denied for relation clips",
      "ERROR: relation \"camera_archive\" does not exist",
      "FATAL: role \"backup\" does not exist",
    ]);
  }

  return `ERROR: unsupported startup payload ${sanitizeText(payload, context.serviceMemory.host, 120)}`;
}
