import { PersonaStateValue } from "../profiles/personaLibrary.js";
import { ResponderContext } from "./types.js";

function buildResponse(transactionId: number, unitId: number, functionCode: number, payload: Buffer) {
  const length = payload.length + 2;
  const header = Buffer.alloc(7);
  header.writeUInt16BE(transactionId, 0);
  header.writeUInt16BE(0, 2);
  header.writeUInt16BE(length, 4);
  header.writeUInt8(unitId, 6);
  return Buffer.concat([header, Buffer.from([functionCode]), payload]);
}

function toRegister(value: PersonaStateValue) {
  const numeric = typeof value === "number" ? value : value === true ? 1 : 0;
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(Math.max(0, Math.min(65535, numeric)), 0);
  return buffer;
}

function parseWriteSingleRegister(chunk: Buffer) {
  return {
    register: chunk.readUInt16BE(8),
    value: chunk.readUInt16BE(10),
  };
}

function parseWriteMultipleRegisters(chunk: Buffer) {
  const register = chunk.readUInt16BE(8);
  const count = chunk.readUInt16BE(10);
  const values: number[] = [];
  for (let index = 0; index < count; index += 1) {
    values.push(chunk.readUInt16BE(13 + index * 2));
  }
  return { register, count, values };
}

function mapRegisterPatch(register: number, value: number): Record<string, PersonaStateValue> {
  if (register === 0) {
    return { pressure_kpa: value };
  }
  if (register === 1) {
    return { motor_rpm: value };
  }
  if (register === 2) {
    return { alarm: value > 0 };
  }
  return {};
}

export function buildModbusReply(params: {
  action: string;
  transactionId: number;
  unitId: number;
  functionCode: number;
  chunk: Buffer;
  context: ResponderContext;
}) {
  const { action, transactionId, unitId, functionCode, chunk, context } = params;
  const state = context.serviceMemory.deviceState;

  if (action === "fake_error") {
    return {
      buffer: buildResponse(transactionId, unitId, functionCode | 0x80, Buffer.from([0x04])),
    };
  }

  if (functionCode === 0x01) {
    const alarm = Boolean(state.alarm);
    return {
      buffer: buildResponse(transactionId, unitId, functionCode, Buffer.from([0x01, alarm ? 0x01 : 0x00])),
    };
  }

  if (functionCode === 0x03 || functionCode === 0x04) {
    const pressure = toRegister(state.pressure_kpa || 125);
    const rpm = toRegister(state.motor_rpm || 300);
    return {
      buffer: buildResponse(transactionId, unitId, functionCode, Buffer.from([0x04, pressure[0], pressure[1], rpm[0], rpm[1]])),
    };
  }

  if (functionCode === 0x06) {
    const parsed = parseWriteSingleRegister(chunk);
    return {
      buffer: buildResponse(transactionId, unitId, functionCode, chunk.subarray(8, 12)),
      patch: { deviceState: mapRegisterPatch(parsed.register, parsed.value) },
    };
  }

  if (functionCode === 0x10) {
    const parsed = parseWriteMultipleRegisters(chunk);
    const deviceState = parsed.values.reduce<Record<string, PersonaStateValue>>((acc, value, index) => {
      Object.assign(acc, mapRegisterPatch(parsed.register + index, value));
      return acc;
    }, {});
    return {
      buffer: buildResponse(transactionId, unitId, functionCode, Buffer.from([chunk[8], chunk[9], chunk[10], chunk[11]])),
      patch: { deviceState },
    };
  }

  return {
    buffer: buildResponse(transactionId, unitId, functionCode | 0x80, Buffer.from([0x01])),
  };
}
