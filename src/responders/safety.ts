const secretPatterns = [
  /\bOPENAI_[A-Z0-9_]*=[^\s]+/gi,
  /\bAWS_[A-Z0-9_]*=[^\s]+/gi,
  /\b[A-Z0-9_]*API[_-]?KEY=[^\s]+/gi,
  /\b[A-Z0-9_]*SECRET[_-]?(KEY)?=[^\s]+/gi,
  /\bBearer\s+[A-Za-z0-9._-]+\b/g,
  /\bpostgresql:\/\/[^\s'"]+\b/gi,
];

const localHostPatterns = [/\blocalhost\b/gi, /\b127\.0\.0\.1\b/g, /\b0\.0\.0\.0\b/g];

function sanitizeString(value: string, replacementHost = "relay.internal", maxLength = 4096) {
  let sanitized = value;

  for (const pattern of secretPatterns) {
    sanitized = sanitized.replace(pattern, "[redacted]");
  }

  for (const pattern of localHostPatterns) {
    sanitized = sanitized.replace(pattern, replacementHost);
  }

  if (sanitized.length > maxLength) {
    sanitized = `${sanitized.slice(0, maxLength - 3)}...`;
  }

  return sanitized;
}

export function sanitizeText(value: string, replacementHost?: string, maxLength?: number) {
  return sanitizeString(value, replacementHost, maxLength);
}

export function sanitizeUnknown(value: unknown, replacementHost?: string): unknown {
  if (typeof value === "string") {
    return sanitizeString(value, replacementHost);
  }

  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeUnknown(entry, replacementHost));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
        key,
        sanitizeUnknown(entry, replacementHost),
      ])
    );
  }

  return value;
}

export function sanitizeMetadata(
  metadata: Record<string, unknown> | undefined,
  replacementHost?: string
): Record<string, unknown> | undefined {
  if (!metadata) {
    return undefined;
  }

  return sanitizeUnknown(metadata, replacementHost) as Record<string, unknown>;
}

export function safeShellOutput(value: string, replacementHost?: string) {
  return sanitizeString(value, replacementHost, 2048);
}
