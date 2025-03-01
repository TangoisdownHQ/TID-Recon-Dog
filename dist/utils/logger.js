var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
// src/utils/logger.ts
import fs from 'fs/promises';
import path from 'path';
import PQueue from 'p-queue';
// Get the directory path of the current module (ES Module workaround for __dirname)
const __dirname = new URL('.', import.meta.url).pathname;
// Define log file path
const logFilePath = path.join(__dirname, '../../logs/connections.log');
const logQueue = new PQueue({ concurrency: 5 });
// **Mock data enrichment function (Replaces worker threads)**
function mockEnrichData(ip) {
    return __awaiter(this, void 0, void 0, function* () {
        // Simulate a simple IP-based lookup (Replace this with real enrichment later)
        return new Promise((resolve) => setTimeout(() => resolve(`GeoIP: MockLocation for ${ip}`), 1000) // Simulated delay
        );
    });
}
// **Asynchronous function to log interactions (without workers)**
export const logInteraction = (service, ip, details) => __awaiter(void 0, void 0, void 0, function* () {
    const enrichedData = yield mockEnrichData(ip); // Enrich data directly (no worker thread)
    const logMessage = `[${new Date().toISOString()}] ${service} - IP: ${ip} - ${details} - ${enrichedData}`;
    // Add the logging task to the queue to control concurrency
    yield logQueue.add(() => fs.appendFile(logFilePath, logMessage + '\n'));
});
