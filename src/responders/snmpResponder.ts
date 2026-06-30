import { ResponderContext } from "./types.js";

// Build minimal SNMP v1/v2c GetResponse frames for common MIB-II OIDs.

function tlv(tag: number, value: Buffer): Buffer {
  const len = value.length;
  if (len < 128) {
    return Buffer.concat([Buffer.from([tag, len]), value]);
  }
  // Short-form long length (≤ 255 bytes)
  return Buffer.concat([Buffer.from([tag, 0x81, len]), value]);
}

function integer(val: number): Buffer {
  return tlv(0x02, Buffer.from([val & 0xff]));
}

function octetString(str: string): Buffer {
  return tlv(0x04, Buffer.from(str, "utf8"));
}

function oidBytes(oid: number[]): Buffer {
  const encoded: number[] = [40 * oid[0] + oid[1]];
  for (const part of oid.slice(2)) {
    if (part < 128) {
      encoded.push(part);
    } else {
      encoded.push(0x80 | (part >> 7), part & 0x7f);
    }
  }
  return tlv(0x06, Buffer.from(encoded));
}

function sequence(contents: Buffer): Buffer {
  return tlv(0x30, contents);
}

function buildVarBind(oidOctets: Buffer, valueBuffer: Buffer): Buffer {
  return sequence(Buffer.concat([oidOctets, valueBuffer]));
}

function extractRequestId(msg: Buffer): number {
  // Attempt a simple heuristic to read the request-id from the incoming PDU.
  // Typical structure: SEQUENCE > INTEGER(version) > OCTET(community) > PDU
  try {
    if (msg.length < 12) return 1;
    // Skip outer SEQUENCE and version INTEGER
    let offset = 2; // skip tag+len
    if (msg[1] > 127) offset += msg[1] - 128 + 1; // long-form length
    offset += 2; // skip version tag+len+value
    if (msg[offset - 1] > 1) offset += msg[offset - 1] - 1; // multi-byte version
    offset += msg[offset + 1] + 2; // skip community string
    offset += 2; // PDU tag + len
    offset += 2; // skip request-id tag
    const len = msg[offset];
    offset += 1;
    let id = 0;
    for (let i = 0; i < len && offset + i < msg.length; i++) {
      id = (id << 8) | msg[offset + i];
    }
    return id || 1;
  } catch {
    return 1;
  }
}

export function buildSnmpReply(request: Buffer, context: ResponderContext): Buffer {
  const { serviceMemory, persona } = context;
  const pressure = Number(serviceMemory.deviceState.pressure_kpa ?? 125);
  const motorRpm = Number(serviceMemory.deviceState.motor_rpm ?? 300);
  const alarm = Boolean(serviceMemory.deviceState.alarm);
  const requestId = extractRequestId(request);

  const sysDescrOid = oidBytes([1, 3, 6, 1, 2, 1, 1, 1, 0]);
  const sysDescrVal = octetString(`${persona.displayName} ${serviceMemory.host}`);

  const sysObjectIdOid = oidBytes([1, 3, 6, 1, 2, 1, 1, 2, 0]);
  const sysObjectIdVal = oidBytes([1, 3, 6, 1, 4, 1, 3833, 1, 1]);

  const sysUptimeOid = oidBytes([1, 3, 6, 1, 2, 1, 1, 3, 0]);
  const uptimeTicks = (Number(serviceMemory.deviceState.uptime_hours ?? 438) * 360000) & 0xffffffff;
  const uptimeBytes = Buffer.from([
    (uptimeTicks >> 24) & 0xff,
    (uptimeTicks >> 16) & 0xff,
    (uptimeTicks >> 8) & 0xff,
    uptimeTicks & 0xff,
  ]);
  const sysUptimeVal = tlv(0x43, uptimeBytes); // TimeTicks

  const sysDescrEntry = buildVarBind(sysDescrOid, sysDescrVal);
  const sysObjectIdEntry = buildVarBind(sysObjectIdOid, sysObjectIdVal);
  const sysUptimeEntry = buildVarBind(sysUptimeOid, sysUptimeVal);

  // Custom enterprise OIDs for pressure and RPM (Schneider-like)
  const pressureOid = oidBytes([1, 3, 6, 1, 4, 1, 3833, 2, 1, 1, 0]);
  const pressureVal = tlv(0x41, Buffer.from([(pressure >> 8) & 0xff, pressure & 0xff])); // Gauge32
  const pressureEntry = buildVarBind(pressureOid, pressureVal);

  const rpmOid = oidBytes([1, 3, 6, 1, 4, 1, 3833, 2, 1, 2, 0]);
  const rpmVal = tlv(0x41, Buffer.from([(motorRpm >> 8) & 0xff, motorRpm & 0xff]));
  const rpmEntry = buildVarBind(rpmOid, rpmVal);

  const alarmOid = oidBytes([1, 3, 6, 1, 4, 1, 3833, 2, 1, 3, 0]);
  const alarmVal = integer(alarm ? 1 : 0);
  const alarmEntry = buildVarBind(alarmOid, alarmVal);

  const varBindList = sequence(Buffer.concat([
    sysDescrEntry,
    sysObjectIdEntry,
    sysUptimeEntry,
    pressureEntry,
    rpmEntry,
    alarmEntry,
  ]));

  const reqIdBuf = Buffer.from([
    (requestId >> 24) & 0xff,
    (requestId >> 16) & 0xff,
    (requestId >> 8) & 0xff,
    requestId & 0xff,
  ]);
  const pduBody = Buffer.concat([
    tlv(0x02, reqIdBuf),  // request-id
    integer(0),            // error-status: noError
    integer(0),            // error-index
    varBindList,
  ]);
  const pdu = tlv(0xa2, pduBody); // GetResponse PDU

  const version = integer(0); // SNMP v1
  const community = octetString("public");
  const messageBody = Buffer.concat([version, community, pdu]);
  return sequence(messageBody);
}
