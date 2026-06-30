import { listFileNames, pickDeterministic } from "./common.js";
import { ResponderContext } from "./types.js";

export function buildFtpGreeting(context: ResponderContext) {
  return context.serviceMemory.banner;
}

export function buildFtpLoginFailure(action: string, username: string, context: ResponderContext) {
  if (action === "fake_error") {
    return "421 Service not available, closing control connection.";
  }

  if (action === "decoy_success") {
    return `421 Transfer queue saturated on ${context.serviceMemory.host}`;
  }

  return pickDeterministic(`${context.attacker.id}:${username}`, [
    "530 Login incorrect.",
    "530 Authentication failed.",
    "530 User account locked.",
    `530 Account ${username || "unknown"} rejected by ${context.serviceMemory.host}.`,
  ]);
}

export function buildFtpFileListing(context: ResponderContext) {
  return listFileNames(context.serviceMemory.files);
}
