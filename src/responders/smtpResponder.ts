import { ResponderContext } from "./types.js";

export type SmtpStage = "greeting" | "command" | "data" | "done";

const QUEUE_ID_CHARS = "ABCDEFGHJKLMNPQRSTVWXYZ0123456789";

function queueId(): string {
  return Array.from({ length: 12 }, () => QUEUE_ID_CHARS[Math.floor(Math.random() * QUEUE_ID_CHARS.length)]).join("");
}

export function buildSmtpBanner(context: ResponderContext): string {
  return `220 ${context.serviceMemory.host} ESMTP Postfix (Ubuntu)\r\n`;
}

export function buildSmtpReply(input: string, stage: SmtpStage, context: ResponderContext): string {
  const host = context.serviceMemory.host;
  const cmd = input.split(/\s/)[0].toUpperCase();

  if (stage === "data") {
    if (input.trim() === ".") {
      return `250 2.0.0 Ok: queued as ${queueId()}\r\n`;
    }
    // Absorb body lines silently
    return "";
  }

  switch (cmd) {
    case "EHLO":
    case "HELO":
      return [
        `250-${host} Hello`,
        "250-PIPELINING",
        "250-SIZE 10240000",
        "250-VRFY",
        "250-ETRN",
        "250-STARTTLS",
        "250-AUTH PLAIN LOGIN",
        "250 8BITMIME",
      ].join("\r\n") + "\r\n";

    case "MAIL":
      return "250 2.1.0 Ok\r\n";

    case "RCPT":
      return "250 2.1.5 Ok\r\n";

    case "DATA":
      return "354 End data with <CR><LF>.<CR><LF>\r\n";

    case "VRFY":
      return "252 Cannot VRFY user, but will accept message and attempt delivery\r\n";

    case "AUTH":
      return "535 5.7.8 Authentication credentials invalid\r\n";

    case "NOOP":
      return "250 Ok\r\n";

    case "RSET":
      return "250 Ok\r\n";

    case "QUIT":
      return `221 2.0.0 Bye\r\n`;

    case "STARTTLS":
      return "454 4.7.0 TLS not available due to local problem\r\n";

    default:
      return "502 5.5.2 Error: command not recognized\r\n";
  }
}
