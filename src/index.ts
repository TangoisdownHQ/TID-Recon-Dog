import { startHttpService } from "./services/httpService.js";
import { startSshService } from "./services/sshService.js";
import { startPgService } from "./services/pgService.js";
import { startFtpService } from "./services/ftpService.js";
import { startRtspService } from "./services/rtspService.js";
import { startRdpService } from "./services/rdpService.js";
import { startTelnetService } from "./services/telnetService.js";
import { startModbusService } from "./services/modbusService.js";
import { startSnmpService } from "./services/snmpService.js";
import { startSmtpService } from "./services/smtpService.js";
import { formatConsole, readSessionSnapshots } from "./utils/logger.js";
import {
  isValidAction,
  readControlState,
  setDefaultAction,
  setSessionAction,
  validActions,
} from "./operator/controlPlane.js";
import { runWatchMode } from "./operator/watch.js";
import { listServiceProfiles } from "./profiles/serviceProfiles.js";
import { exportTrainingDataset } from "./datasets/exporter.js";
import { generateCtManifest } from "./pipeline/ctPipeline.js";
import { exportEvalSuite, scoreEvalResponses } from "./pipeline/evaluator.js";
import { runEvalSuite } from "./pipeline/evalRunner.js";
import { listAttackers, getAttackerById } from "./deception_engine/state/attacker_memory.js";
import { exportProtocolTranscripts } from "./datasets/transcriptExporter.js";
import { exportCloudBundle } from "./cloud/bundle.js";
import { listPersonas } from "./profiles/personaLibrary.js";
import { startOperatorServer } from "./operator/api/metricsServer.js";
import { spawn } from "child_process";
import path from "path";
import { buildIocs, buildAttackMatrix, buildCampaigns } from "./cti/iocEngine.js";
import { buildStixBundle, buildMispEvent, buildBlocklist } from "./cti/export.js";
import { ingestFeeds } from "./cti/feeds.js";
import { refreshDarkweb, readDarkwebHits } from "./cti/darkweb.js";
import { printLogo } from "./utils/logo.js";

type ServiceName =
  | "http"
  | "ssh"
  | "postgres"
  | "ftp"
  | "rtsp"
  | "rdp"
  | "telnet"
  | "modbus"
  | "snmp"
  | "smtp";

type StartedService = { name: string; host: string; port: number };
type FailedService = { service: ServiceName; reason: string };

const starters: Record<ServiceName, () => Promise<{ name: string; host: string; port: number }>> = {
  http: startHttpService,
  ssh: startSshService,
  postgres: startPgService,
  ftp: startFtpService,
  rtsp: startRtspService,
  rdp: startRdpService,
  telnet: startTelnetService,
  modbus: startModbusService,
  snmp: startSnmpService,
  smtp: startSmtpService,
};

function allServices() {
  return Object.keys(starters) as ServiceName[];
}

function printUsage() {
  console.log(`TID-Recon-Dog CLI

Usage:
  node dist/index.js start [all|http|ssh|ftp|postgres|rtsp|rdp|telnet|modbus|snmp|smtp ...]
  node dist/index.js start tidrecondog
  node dist/index.js sessions
  node dist/index.js attackers
  node dist/index.js attacker <id>
  node dist/index.js watch
  node dist/index.js dashboard
  node dist/index.js serve-dashboard
  node dist/index.js profiles
  node dist/index.js personas
  node dist/index.js export-dataset [output.jsonl] [source1.csv source2.jsonl ...]
  node dist/index.js export-transcripts [output.jsonl] [service]
  node dist/index.js ct-manifest [output.json] [corpus.jsonl]
  node dist/index.js export-eval-suite [output.jsonl]
  node dist/index.js run-eval [suite.jsonl] [responses.jsonl]
  node dist/index.js score-eval <responses.jsonl> [suite.jsonl] [output.json]
  node dist/index.js cloud-bundle [output-dir]
  node dist/index.js control show
  node dist/index.js control set default <${validActions.join("|")}>
  node dist/index.js control set session <sessionId> <${validActions.join("|")}>
  node dist/index.js retrain [--force] [--export-only]

Environment variables:
  ALERT_WEBHOOK_URL          POST alert payload here on risk escalation
  PERSONA_ROTATE_AFTER_HOURS Rotate attacker personas after N hours (0 = never)
  MAX_CONNECTIONS_PER_IP     Per-service connection cap per IP (default: 25)
  EVAL_PROVIDER              ollama | anthropic | openai (default: ollama)
  EVAL_MODEL                 Model name for run-eval (default: llama3 / claude-haiku-4-5-20251001)
  EVAL_API_URL               Override API endpoint for run-eval
  EVAL_API_KEY               API key for run-eval (or ANTHROPIC_API_KEY)
`);
}

function resolveRequestedServices(args: string[]) {
  if (args.length === 0 || args.includes("all")) {
    return allServices();
  }

  return args.filter((arg): arg is ServiceName => arg in starters);
}

function portEnvVarName(service: ServiceName) {
  return `${service.toUpperCase()}_PORT`;
}

function describeStartFailure(service: ServiceName, error: unknown) {
  const errorCode = typeof error === "object" && error !== null && "code" in error
    ? String((error as { code?: unknown }).code)
    : "";

  if (errorCode === "EADDRINUSE") {
    return `port already in use; set ${portEnvVarName(service)} to a free port`;
  }

  if (errorCode === "EPERM") {
    return `port bind blocked; confirm permission or set ${portEnvVarName(service)} to an allowed port`;
  }

  return String(error);
}

async function maybeStartOperator() {
  if (process.env.OPERATOR_DISABLE === "1") {
    return null;
  }
  try {
    return await startOperatorServer();
  } catch (error) {
    console.error(formatConsole(`Operator console failed to start: ${describeStartFailure("http", error)}`));
    return null;
  }
}

async function bootServices(requested: ServiceName[]) {
  const results = await Promise.allSettled(requested.map(async (service) => starters[service]()));
  const started: StartedService[] = [];
  const failed: FailedService[] = [];

  results.forEach((result, index) => {
    const service = requested[index];
    if (result.status === "fulfilled") {
      started.push(result.value);
      return;
    }

    failed.push({
      service,
      reason: describeStartFailure(service, result.reason),
    });
  });

  return { started, failed };
}

async function startServices(args: string[]) {
  printLogo();
  const requested = resolveRequestedServices(args);

  if (requested.length === 0) {
    printUsage();
    process.exitCode = 1;
    return;
  }

  const { started, failed } = await bootServices(requested);

  if (started.length === 0) {
    console.error("Failed to start requested services.");
    for (const failure of failed) {
      console.error(`- ${failure.service.toUpperCase()}: ${failure.reason}`);
    }
    process.exitCode = 1;
    return;
  }

  for (const service of started) {
    console.log(formatConsole(`${service.name.toUpperCase()} listening on ${service.host}:${service.port}`));
  }

  if (failed.length > 0) {
    console.log("");
    console.log("Services that did not start:");
    for (const failure of failed) {
      console.log(`- ${failure.service.toUpperCase()}: ${failure.reason}`);
    }
    console.log("");
  }

  await maybeStartOperator();

  console.log(formatConsole("Operator control is file-backed. Use `control set` commands to change actions in realtime."));
}

async function launchTidReconDog() {
  printLogo();
  const requested = allServices();
  const { started, failed } = await bootServices(requested);

  if (started.length === 0) {
    console.error("Failed to start requested services.");
    for (const failure of failed) {
      console.error(`- ${failure.service.toUpperCase()}: ${failure.reason}`);
    }
    process.exitCode = 1;
    return;
  }

  const operator = await maybeStartOperator();

  const startupSummary = [
    failed.length === 0
      ? "Started all services and opened the operator TUI."
      : `Started ${started.length} services and opened the operator TUI.`,
    ...started.map((service) => `${service.name.toUpperCase()} listening on ${service.host}:${service.port}`),
    ...failed.map((failure) => `${failure.service.toUpperCase()} failed: ${failure.reason}`),
    operator
      ? `OPERATOR GUI on http://${operator.host}:${operator.port}/ (token printed above)`
      : "OPERATOR GUI disabled (OPERATOR_DISABLE=1)",
    "Use the menu or type a number to switch views.",
  ].join("\n");

  await runWatchMode({
    initialView: { mode: "menu" },
    message: startupSummary,
  });
}

async function showSessions() {
  const sessions = await readSessionSnapshots();
  if (sessions.length === 0) {
    console.log("No sessions recorded yet.");
    return;
  }

  for (const session of sessions) {
    console.log(
      [
        session.id,
        session.service,
        session.ip,
        session.status,
        session.currentAction,
        session.lastSeenAt,
      ].join(" | ")
    );
  }
}

async function showAttackers() {
  const attackers = await listAttackers();
  if (attackers.length === 0) {
    console.log("No attackers profiled yet.");
    return;
  }

  for (const attacker of attackers) {
    const geoStr = attacker.geo ? `${attacker.geo.countryCode}/${attacker.geo.isp.slice(0, 20)}` : "unknown";
    console.log(
      [
        attacker.id.slice(0, 12),
        attacker.sourceIp,
        geoStr,
        attacker.intent,
        attacker.risk,
        attacker.totalScore,
        Object.keys(attacker.services).join(","),
        attacker.lastSeenAt,
      ].join(" | ")
    );
  }
}

async function showAttacker(id: string) {
  const attacker = await getAttackerById(id);
  if (!attacker) {
    // Try prefix match
    const all = await listAttackers();
    const match = all.find((a) => a.id.startsWith(id));
    if (!match) {
      console.log(`Attacker ${id} not found.`);
      process.exitCode = 1;
      return;
    }
    console.log(JSON.stringify(match, null, 2));
    return;
  }
  console.log(JSON.stringify(attacker, null, 2));
}

function showProfiles() {
  for (const profile of listServiceProfiles()) {
    console.log(
      [
        profile.service,
        `${profile.product} ${profile.version}`,
        profile.host,
        profile.ports.join(","),
        profile.tags.join(","),
      ].join(" | ")
    );
  }
}

function showPersonas() {
  for (const persona of listPersonas()) {
    console.log(
      [
        persona.id,
        persona.group,
        persona.host,
        persona.realm,
        Object.keys(persona.services).join(","),
      ].join(" | ")
    );
  }
}

async function runExportDataset(args: string[]) {
  const [outputPath, ...externalSources] = args;
  const result = await exportTrainingDataset(outputPath, externalSources);
  console.log(`Exported ${result.records} records to ${result.targetPath}`);
  console.log(`Source snapshots: ${result.sessions} sessions, ${result.logs} log entries, ${result.transcripts} transcripts, ${result.externalSources} external source files`);
}

async function runExportTranscripts(args: string[]) {
  const result = await exportProtocolTranscripts(args[0], args[1]);
  console.log(`Wrote ${result.transcripts} protocol transcripts to ${result.targetPath}`);
}

async function runCtManifest(args: string[]) {
  const [outputPath, corpusPath] = args;
  const result = await generateCtManifest(outputPath, corpusPath);
  console.log(`Wrote CT manifest to ${result.targetPath}`);
}

async function runExportEvalSuite(args: string[]) {
  const result = await exportEvalSuite(args[0]);
  console.log(`Wrote ${result.cases} eval cases to ${result.targetPath}`);
}

async function runEval(args: string[]) {
  const [suitePath, outputPath] = args;
  const result = await runEvalSuite(suitePath, outputPath);
  console.log(`Wrote ${result.cases} responses to ${result.targetPath}`);
}

async function runScoreEval(args: string[]) {
  const [responsePath, suitePath, outputPath] = args;
  if (!responsePath) {
    printUsage();
    process.exitCode = 1;
    return;
  }

  const result = await scoreEvalResponses(responsePath, suitePath, outputPath);
  console.log(`Scored ${result.summary.total_cases} eval responses`);
  console.log(`Passed ${result.summary.passed_cases} with average score ${result.summary.average_score}`);
  console.log(`Wrote score report to ${result.targetPath}`);
}

async function runCloudBundle(args: string[]) {
  const result = await exportCloudBundle(args[0]);
  console.log(`Wrote cloud bundle to ${result.targetPath}`);
  console.log(`Bundle contents: ${result.logs} logs, ${result.sessions} sessions, ${result.attackers} attackers, ${result.transcripts} transcripts`);
}

async function runCti(sub: string, args: string[]) {
  const fs = await import("fs/promises");
  switch (sub) {
    case "iocs": {
      const { iocs, counts } = await buildIocs();
      console.log(JSON.stringify({ counts, iocs: iocs.slice(0, 100) }, null, 2));
      return;
    }
    case "attack":
      console.log(JSON.stringify(await buildAttackMatrix(), null, 2));
      return;
    case "stix": {
      const out = args[0] || "exports/stix-bundle.json";
      await fs.mkdir(path.dirname(out), { recursive: true });
      await fs.writeFile(out, JSON.stringify(await buildStixBundle(), null, 2));
      console.log(`Wrote STIX 2.1 bundle to ${out}`);
      return;
    }
    case "misp": {
      const out = args[0] || "exports/misp-event.json";
      await fs.mkdir(path.dirname(out), { recursive: true });
      await fs.writeFile(out, JSON.stringify(await buildMispEvent(), null, 2));
      console.log(`Wrote MISP event to ${out}`);
      return;
    }
    case "blocklist": {
      const out = args[0] || "exports/blocklist.txt";
      await fs.mkdir(path.dirname(out), { recursive: true });
      await fs.writeFile(out, (await buildBlocklist()).txt);
      console.log(`Wrote blocklist to ${out}`);
      return;
    }
    case "ingest-feeds": {
      const r = await ingestFeeds();
      console.log(`Ingested ${r.feeds} feeds, blocked ${r.blocked} IPs`);
      return;
    }
    case "darkweb": {
      const r = await refreshDarkweb();
      console.log(`Dark-web: scanned ${r.feeds} feeds, ${r.hits} new correlations`);
      const hits = await readDarkwebHits(10);
      hits.forEach((h) => console.log(`  ${h.type} ${h.indicator} @ ${h.source}`));
      return;
    }
    case "report": {
      const date = new Date().toISOString().slice(0, 10);
      const dir = args[0] || "exports";
      const { iocs, counts } = await buildIocs();
      const attack = await buildAttackMatrix();
      const campaigns = await buildCampaigns();
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(`${dir}/stix-${date}.json`, JSON.stringify(await buildStixBundle(), null, 2));
      const md = [
        `# TID-Recon-Dog Threat Intel Report — ${date}`,
        ``,
        `## IOC summary`,
        ...Object.entries(counts).map(([k, v]) => `- ${k}: ${v}`),
        ``,
        `## MITRE ATT&CK techniques observed`,
        ...attack.map((t) => `- ${t.id} ${t.name} (${t.tactic}) — ${t.count} obs`),
        ``,
        `## Campaigns`,
        ...campaigns.map((c) => `- ${c.origin} / ${c.intent} — ${c.members} members, score ${c.totalScore}`),
        ``,
        `## Top indicators`,
        ...iocs.slice(0, 25).map((i) => `- [${i.type}] ${i.value} (x${i.count})`),
      ].join("\n");
      await fs.writeFile(`${dir}/intel-report-${date}.md`, md);
      console.log(`Wrote ${dir}/intel-report-${date}.md and ${dir}/stix-${date}.json`);
      return;
    }
    default:
      console.log("cti subcommands: iocs | attack | stix [out] | misp [out] | blocklist [out] | ingest-feeds | darkweb | report [dir]");
      process.exitCode = 1;
  }
}

async function runRetrain(args: string[]) {
  const scriptPath = path.resolve("mlops/tidrc-ml-pipeline/scripts/auto_retrain.sh");
  const env: NodeJS.ProcessEnv = { ...process.env };
  if (args.includes("--force")) env.RETRAIN_FORCE = "1";
  if (args.includes("--export-only")) env.RETRAIN_BACKEND = "none";

  console.log(formatConsole(`Launching retrain: ${scriptPath}`));
  const code = await new Promise<number>((resolve) => {
    const child = spawn("bash", [scriptPath], { env, stdio: "inherit" });
    child.on("error", (error) => {
      console.error(`Failed to launch retrain: ${error.message}`);
      resolve(1);
    });
    child.on("exit", (exitCode) => resolve(exitCode ?? 0));
  });

  if (code !== 0) {
    process.exitCode = code;
  }
}

async function handleControl(args: string[]) {
  const [subcommand, scope, subject, action] = args;

  if (subcommand === "show") {
    console.log(JSON.stringify(await readControlState(), null, 2));
    return;
  }

  if (subcommand !== "set") {
    printUsage();
    process.exitCode = 1;
    return;
  }

  if (scope === "default" && subject && isValidAction(subject)) {
    await setDefaultAction(subject);
    console.log(`Default action set to ${subject}`);
    return;
  }

  if (scope === "session" && subject && action && isValidAction(action)) {
    await setSessionAction(subject, action);
    console.log(`Session ${subject} action set to ${action}`);
    return;
  }

  printUsage();
  process.exitCode = 1;
}

async function main() {
  const [command, ...args] = process.argv.slice(2);

  switch (command) {
    case "start":
      if (args[0] === "tidrecondog") {
        await launchTidReconDog();
      } else {
        await startServices(args);
      }
      break;
    case "sessions":
      await showSessions();
      break;
    case "attackers":
      await showAttackers();
      break;
    case "attacker":
      if (args[0]) {
        await showAttacker(args[0]);
      } else {
        printUsage();
        process.exitCode = 1;
      }
      break;
    case "watch":
    case "dashboard":
      await runWatchMode();
      break;
    case "serve-dashboard":
    case "serve": {
      const operator = await maybeStartOperator();
      if (!operator) {
        console.error("Operator console disabled or failed to start.");
        process.exitCode = 1;
        return;
      }
      // Keep the process alive serving the GUI/API.
      await new Promise<never>(() => {});
      break;
    }
    case "profiles":
      showProfiles();
      break;
    case "personas":
      showPersonas();
      break;
    case "export-dataset":
      await runExportDataset(args);
      break;
    case "export-transcripts":
      await runExportTranscripts(args);
      break;
    case "ct-manifest":
      await runCtManifest(args);
      break;
    case "export-eval-suite":
      await runExportEvalSuite(args);
      break;
    case "run-eval":
      await runEval(args);
      break;
    case "score-eval":
      await runScoreEval(args);
      break;
    case "cloud-bundle":
      await runCloudBundle(args);
      break;
    case "control":
      await handleControl(args);
      break;
    case "retrain":
      await runRetrain(args);
      break;
    case "cti":
      await runCti(args[0], args.slice(1));
      break;
    default:
      printUsage();
      process.exitCode = 1;
  }
}

void main();
