//src/services/sshService.ts
import pkg from 'ssh2';
const { Server } = pkg; // Import Server from ssh2
import { logInteraction } from '../utils/logger.js';
import { config } from '../config/config.js';
import fs from 'fs';
import path from 'path';
// Fix for ES Module: Get __dirname equivalent
const __dirname = new URL('.', import.meta.url).pathname;
// Load SSH Host Key
const hostKey = fs.readFileSync(path.join(__dirname, '../../host.key'));
const honeypotID = 'honeypot-01';
// Function to extract real IP from SSH connection
const getClientIP = (client) => { var _a; return ((_a = client._socket) === null || _a === void 0 ? void 0 : _a.remoteAddress) || 'unknown'; };
const sshServer = new Server({ hostKeys: [hostKey] }, (client) => {
    const remoteAddress = getClientIP(client);
    logInteraction('SSH', remoteAddress, `Connection established to honeypot ID: ${honeypotID}`);
    client.on('authentication', (ctx) => {
        const attemptDetails = `Username: ${ctx.username}, Method: ${ctx.method}`;
        logInteraction('SSH', remoteAddress, `Authentication attempt - ${attemptDetails}`);
        setTimeout(() => {
            ctx.reject();
            logInteraction('SSH', remoteAddress, 'Authentication failed');
        }, 5000);
    });
    client.on('ready', () => {
        client.on('session', (accept) => {
            logInteraction('SSH', remoteAddress, 'Rejected session attempt');
            // Reject the session immediately
            const rejectSession = accept();
            rejectSession.end('Session rejected');
        });
    });
    client.on('end', () => {
        logInteraction('SSH', remoteAddress, `Connection closed to honeypot ID: ${honeypotID}`);
    });
});
// Start the SSH honeypot service
sshServer.listen(config.services.ssh.port, config.services.ssh.host, () => {
    console.log(`SSH service running on ${config.services.ssh.host}:${config.services.ssh.port}`);
});
