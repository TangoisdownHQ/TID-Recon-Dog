#!/usr/bin/env node

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const [, , commandName, ...args] = process.argv;

if (commandName !== "tidrecondog") {
  console.error("Usage: start tidrecondog");
  process.exit(1);
}

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const entrypoint = path.join(scriptDirectory, "..", "dist", "index.js");
const child = spawn(process.execPath, [entrypoint, "start", "tidrecondog", ...args], {
  stdio: "inherit",
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }

  process.exit(code ?? 0);
});
