import { renderShellOutput } from "./common.js";
import { safeShellOutput } from "./safety.js";
import { ResponderContext } from "./types.js";

function jitter(base: number, variance: number): number {
  return base + Math.floor(Math.random() * variance * 2) - variance;
}

export function buildSshAuthentication(action: string) {
  if (action === "stall") {
    return { accept: false, delayMs: jitter(7000, 900) };
  }
  if (action === "decoy_success") {
    return { accept: true, delayMs: jitter(1200, 250) };
  }
  if (action === "fake_error") {
    return { accept: false, delayMs: jitter(600, 180) };
  }
  return { accept: false, delayMs: jitter(2500, 450) };
}

export function buildSshShellIntro(context: ResponderContext, action: string, username: string) {
  const effectiveUser = username || context.serviceMemory.usernames[0] || "admin";
  return [
    context.serviceMemory.banner,
    `Linux ${context.serviceMemory.host} 5.15.0-91-generic #101-Ubuntu SMP x86_64`,
    action === "stall"
      ? "Last login: timeout while syncing profile..."
      : "Last login: Tue Apr 15 05:14:27 UTC 2026",
  ].join("\n");
}

export function buildSshCommandOutput(command: string, context: ResponderContext, username: string) {
  return safeShellOutput(renderShellOutput(command, context, username), context.serviceMemory.host);
}
