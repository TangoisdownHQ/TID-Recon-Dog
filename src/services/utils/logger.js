"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logConnection = void 0;
// src/services/utils/logger.ts
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const logFilePath = path_1.default.join(__dirname, '../../../logs/connections.log');
// Function to log connection attempts and interactions
const logConnection = (service, ip, port, status) => {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] ${service} connection from ${ip} on port ${port} - ${status}`;
    fs_1.default.appendFileSync(logFilePath, logMessage + '\n');
};
exports.logConnection = logConnection;
