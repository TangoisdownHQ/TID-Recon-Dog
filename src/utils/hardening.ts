// Anti-fingerprinting helpers — make decoy services behave like the real
// products they imitate (defensive realism), not like a framework default.

/**
 * Randomized response delay to mimic network + processing variance. Honeypots
 * that answer instantly and with uniform latency are easy to flag; real
 * services jitter. Keep it small so it does not look like an artificial stall.
 */
export function jitter(minMs = 3, maxMs = 40): Promise<void> {
  const ms = minMs + Math.floor(Math.random() * (maxMs - minMs + 1));
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** "Server: nginx/1.24.0" -> "nginx/1.24.0" */
export function serverTokenFromBanner(banner: string): string {
  return banner.replace(/^Server:\s*/i, "").trim() || "nginx";
}

const STATUS_TEXT: Record<number, string> = {
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  429: "Too Many Requests",
  500: "Internal Server Error",
  502: "Bad Gateway",
  503: "Service Temporarily Unavailable",
  504: "Gateway Time-out",
};

/**
 * Byte-for-byte nginx-style error body (matches the default nginx error page,
 * including CRLFs and the server-token footer shown when server_tokens is on).
 */
export function nginxErrorPage(status: number, serverToken: string): string {
  const text = STATUS_TEXT[status] || "Error";
  return (
    `<html>\r\n` +
    `<head><title>${status} ${text}</title></head>\r\n` +
    `<body>\r\n` +
    `<center><h1>${status} ${text}</h1></center>\r\n` +
    `<hr><center>${serverToken}</center>\r\n` +
    `</body>\r\n` +
    `</html>\r\n`
  );
}

/**
 * A plausible modern-OpenSSH algorithm offer. ssh2's defaults differ from
 * OpenSSH, which shifts the KEXINIT/HASSH fingerprint; this aligns the offered
 * key-exchange/cipher/MAC/hostkey lists with what OpenSSH 8.9 advertises.
 */
export const opensshAlgorithms = {
  kex: [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
  ],
  // Match the host key we actually serve (RSA). Offering algorithms we can't
  // complete (e.g. ed25519 with no ed25519 key) is itself a tell.
  serverHostKey: [
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
  ],
  cipher: [
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
  ],
  // umac-* are OpenSSH's top MAC preference but ssh2 does not implement them,
  // so we offer the etm + standard HMAC set ssh2 supports. (Means the HASSH
  // MAC field won't be byte-identical to stock OpenSSH — an ssh2 limitation.)
  hmac: [
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
  ],
  compress: ["none", "zlib@openssh.com", "zlib"],
};
