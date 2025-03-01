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
async function mockEnrichData(ip: string): Promise<string> {
  // Simulate a simple IP-based lookup (Replace this with real enrichment later)
  return new Promise((resolve) =>
    setTimeout(() => resolve(`GeoIP: MockLocation for ${ip}`), 1000) // Simulated delay
  );
}

// **Asynchronous function to log interactions (without workers)**
export const logInteraction = async (service: string, ip: string, details: string) => {
  const enrichedData = await mockEnrichData(ip); // Enrich data directly (no worker thread)
  const logMessage = `[${new Date().toISOString()}] ${service} - IP: ${ip} - ${details} - ${enrichedData}`;

  // Add the logging task to the queue to control concurrency
  await logQueue.add(() => fs.appendFile(logFilePath, logMessage + '\n'));
};

