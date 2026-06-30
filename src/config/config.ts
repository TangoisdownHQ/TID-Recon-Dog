import dotenv from "dotenv";

dotenv.config();

const toNumber = (value: string | undefined, fallback: number) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

export const config = {
  services: {
    http: {
      host: process.env.HTTP_HOST || "0.0.0.0",
      port: toNumber(process.env.HTTP_PORT, 3000),
    },
    ssh: {
      host: process.env.SSH_HOST || "0.0.0.0",
      port: toNumber(process.env.SSH_PORT, 2222),
    },
    ftp: {
      host: process.env.FTP_HOST || "0.0.0.0",
      port: toNumber(process.env.FTP_PORT, 2121),
    },
    postgres: {
      host: process.env.POSTGRES_HOST || "0.0.0.0",
      port: toNumber(process.env.POSTGRES_PORT, 5432),
    },
    rtsp: {
      host: process.env.RTSP_HOST || "0.0.0.0",
      port: toNumber(process.env.RTSP_PORT, 8554),
    },
    rdp: {
      host: process.env.RDP_HOST || "0.0.0.0",
      port: toNumber(process.env.RDP_PORT, 3389),
    },
    telnet: {
      host: process.env.TELNET_HOST || "0.0.0.0",
      port: toNumber(process.env.TELNET_PORT, 2323),
    },
    modbus: {
      host: process.env.MODBUS_HOST || "0.0.0.0",
      port: toNumber(process.env.MODBUS_PORT, 1502),
    },
    snmp: {
      host: process.env.SNMP_HOST || "0.0.0.0",
      port: toNumber(process.env.SNMP_PORT, 16100),
    },
    smtp: {
      host: process.env.SMTP_HOST || "0.0.0.0",
      port: toNumber(process.env.SMTP_PORT, 2525),
    },
  },
  operator: {
    // Operator metrics GUI/API. Bind to loopback by default so it is never
    // reachable from the attacker-facing network surface. In k8s this is a
    // ClusterIP reached via port-forward or an authenticated ingress.
    host: process.env.OPERATOR_HOST || "127.0.0.1",
    port: toNumber(process.env.OPERATOR_PORT, 9090),
    // Bearer token required for every API/GUI request. If unset, a token is
    // generated at boot and printed once to the operator console.
    token: process.env.OPERATOR_TOKEN || "",
  },
  ai: {
    // OpenAI-compatible chat-completions endpoint for the trained model.
    // Works with llama.cpp llama-server, Ollama (/v1), vLLM, or a Bedrock proxy.
    // Empty = AI disabled (shadow/ai engine modes fall back to deterministic).
    url: process.env.AI_MODEL_URL || "",
    model: process.env.AI_MODEL || "honeypot-qwen",
    apiKey: process.env.AI_API_KEY || "",
    timeoutMs: toNumber(process.env.AI_TIMEOUT_MS, 12000),
    maxTokens: toNumber(process.env.AI_MAX_TOKENS, 256),
  },
};
