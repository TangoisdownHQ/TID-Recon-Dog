import { renderShellOutput } from "./common.js";
import { safeShellOutput } from "./safety.js";
import { ResponderContext } from "./types.js";

export function buildTelnetBanner(context: ResponderContext) {
  return `${context.persona.displayName} (${context.serviceMemory.host})\r\n${context.serviceMemory.banner} `;
}

export function buildTelnetShellIntro(context: ResponderContext, username: string) {
  return `\r\nBusyBox v${String(context.serviceMemory.deviceState.firmware || "1.35.0")} (built-in shell)\r\n\r\n${username}@${context.serviceMemory.host.split(".")[0]}:~# `;
}

export function buildTelnetCommandOutput(command: string, context: ResponderContext, username: string) {
  return safeShellOutput(renderShellOutput(command, context, username), context.serviceMemory.host);
}
