import { ResponderContext } from "./types.js";

export function buildRtspResponse(cseq: string, status: string, headers: string[], body = "") {
  const contentHeaders = body
    ? [`Content-Type: application/sdp`, `Content-Length: ${Buffer.byteLength(body, "utf8")}`]
    : [];

  return [
    `RTSP/1.0 ${status}`,
    `CSeq: ${cseq || "1"}`,
    ...headers,
    ...contentHeaders,
    "",
    body,
  ].join("\r\n");
}

export function buildRtspUrl(context: ResponderContext) {
  const channel = String(context.serviceMemory.deviceState.channel || "401");
  return `rtsp://${context.serviceMemory.host}/Streaming/Channels/${channel}/`;
}

export function buildRtspHandler(params: {
  action: string;
  method: string;
  headers: Record<string, string>;
  sessionId: string;
  context: ResponderContext;
}) {
  const { action, method, headers, sessionId, context } = params;
  const cseq = headers.cseq || "1";

  if (action === "camera_offline") {
    return buildRtspResponse(cseq, "454 Session Not Found", [`Server: CamWatch Media Relay/4.8.12`]);
  }

  if (action === "fake_error") {
    return buildRtspResponse(cseq, "503 Service Unavailable", [`Server: CamWatch Media Relay/4.8.12`]);
  }

  if (method === "OPTIONS") {
    return buildRtspResponse(cseq, "200 OK", [
      "Server: CamWatch Media Relay/4.8.12",
      "Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE",
    ]);
  }

  if (method === "DESCRIBE") {
    if (!headers.authorization) {
      return buildRtspResponse(cseq, "401 Unauthorized", [
        "Server: CamWatch Media Relay/4.8.12",
        `WWW-Authenticate: Digest realm="${context.persona.realm}", nonce="cf${sessionId.slice(0, 10)}", algorithm=MD5, qop="auth"`,
      ]);
    }

    const sdp = [
      "v=0",
      "o=- 0 0 IN IP4 127.0.0.1",
      `s=${context.persona.displayName}`,
      "t=0 0",
      "a=control:*",
      "m=video 0 RTP/AVP 96",
      `a=rtpmap:96 ${String(context.serviceMemory.deviceState.codec || "H264").toUpperCase()}/90000`,
      "a=fmtp:96 packetization-mode=1; profile-level-id=4D401F; sprop-parameter-sets=Z01AH5WoFAFuQA==,aO48gA==",
      "a=control:trackID=1",
    ].join("\r\n");

    return buildRtspResponse(cseq, "200 OK", [
      "Server: CamWatch Media Relay/4.8.12",
      `Content-Base: ${buildRtspUrl(context)}`,
    ], sdp);
  }

  if (method === "SETUP") {
    return buildRtspResponse(cseq, "200 OK", [
      "Server: CamWatch Media Relay/4.8.12",
      `Transport: ${headers.transport || "RTP/AVP/TCP;unicast;interleaved=0-1"};ssrc=9A7C1120`,
      `Session: ${sessionId.slice(0, 12)};timeout=60`,
    ]);
  }

  if (method === "PLAY") {
    return buildRtspResponse(cseq, "200 OK", [
      "Server: CamWatch Media Relay/4.8.12",
      `Session: ${sessionId.slice(0, 12)};timeout=60`,
      `RTP-Info: url=${buildRtspUrl(context)}trackID=1;seq=9810092;rtptime=3450012`,
    ]);
  }

  return buildRtspResponse(cseq, "400 Bad Request", ["Server: CamWatch Media Relay/4.8.12"]);
}
