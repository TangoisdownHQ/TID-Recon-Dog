import readline from "readline";
import { readTranscripts } from "../deception_engine/logging/transcript_store.js";
import { listAttackers, getAttackerById } from "../deception_engine/state/attacker_memory.js";
import { listPersonas } from "../profiles/personaLibrary.js";
import { listServiceProfiles } from "../profiles/serviceProfiles.js";
import { readSessionSnapshots } from "../utils/logger.js";
import {
  isValidAction,
  readControlState,
  setDefaultAction,
  setSessionAction,
  validActions,
} from "./controlPlane.js";

const navigationText = "Menu: [1] Sessions [2] Attackers [3] Controls [4] Profiles [5] Personas [m] Menu [q] Quit";

const helpText = [
  "Commands:",
  "  menu",
  "  1 / sessions",
  "  2 / attackers",
  "  3 / controls",
  "  4 / profiles",
  "  5 / personas",
  "  show <sessionId>",
  "  attacker <attackerId>",
  "  replay <sessionId>",
  "  refresh",
  `  default <${validActions.join("|")}>`,
  `  set <sessionId> <${validActions.join("|")}>`,
  "  quit",
].join("\n");

type ViewState =
  | { mode: "menu" }
  | { mode: "sessions" }
  | { mode: "attackers" }
  | { mode: "controls" }
  | { mode: "profiles" }
  | { mode: "personas" }
  | { mode: "detail"; sessionId: string }
  | { mode: "attacker"; attackerId: string }
  | { mode: "replay"; sessionId: string };

type WatchModeOptions = {
  initialView?: ViewState;
  message?: string;
};

function truncate(value: string, length: number) {
  if (value.length <= length) return value;
  return `${value.slice(0, Math.max(0, length - 1))}~`;
}

function line(columns: string[]) {
  return columns.join(" | ");
}

function renderHeader(title: string) {
  console.log("TID-Recon-Dog Dashboard");
  console.log(title);
  console.log("");
  console.log(navigationText);
  console.log("");
}

function renderFooter(message = "") {
  console.log("");
  console.log(helpText);
  console.log("");
  if (message) {
    console.log(message);
    console.log("");
  }
}

async function renderMenu(message = "") {
  const [control, sessions, attackers] = await Promise.all([
    readControlState(),
    readSessionSnapshots(),
    listAttackers(),
  ]);

  renderHeader("Launch Menu");
  console.log("Choose a view:");
  console.log("  1. Sessions");
  console.log("  2. Attackers");
  console.log("  3. Controls");
  console.log("  4. Profiles");
  console.log("  5. Personas");
  console.log("");
  console.log(`Live sessions: ${sessions.length}`);
  console.log(`Tracked attackers: ${attackers.length}`);
  console.log(`Default action: ${control.defaultAction}`);
  console.log(`Per-session overrides: ${Object.keys(control.sessionActions).length}`);
  renderFooter(message);
}

async function renderSessions(message = "") {
  const [control, sessions] = await Promise.all([readControlState(), readSessionSnapshots()]);

  renderHeader("Sessions");
  console.log(`Default action: ${control.defaultAction}`);
  console.log(`Per-session overrides: ${Object.keys(control.sessionActions).length}`);
  console.log("");
  console.log(line([
    "session".padEnd(20),
    "service".padEnd(10),
    "ip".padEnd(18),
    "intent".padEnd(13),
    "score".padEnd(5),
    "action".padEnd(15),
    "last seen",
  ]));
  console.log("-".repeat(120));

  const sorted = sessions
    .slice()
    .sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt))
    .slice(0, 15);

  if (sorted.length === 0) {
    console.log("No sessions recorded yet.");
  } else {
    for (const session of sorted) {
      console.log(
        line([
          truncate(session.id, 20).padEnd(20),
          session.service.padEnd(10),
          truncate(session.ip, 18).padEnd(18),
          String(session.intent || "unknown").padEnd(13),
          String(session.score ?? 0).padEnd(5),
          session.currentAction.padEnd(15),
          session.lastSeenAt,
        ])
      );
      const lastEvent = session.events[session.events.length - 1];
      if (lastEvent) console.log(`  ${truncate(lastEvent, 112)}`);
    }
  }

  renderFooter(message);
}

async function renderAttackers(message = "") {
  const attackers = await listAttackers();

  renderHeader("Attackers");
  console.log(line([
    "attacker".padEnd(14),
    "ip".padEnd(18),
    "country".padEnd(8),
    "intent".padEnd(13),
    "risk".padEnd(8),
    "score".padEnd(5),
    "services".padEnd(22),
    "last seen",
  ]));
  console.log("-".repeat(130));

  if (attackers.length === 0) {
    console.log("No attacker profiles recorded yet.");
  } else {
    for (const attacker of attackers.slice(0, 15)) {
      console.log(
        line([
          truncate(attacker.id, 14).padEnd(14),
          truncate(attacker.sourceIp, 18).padEnd(18),
          truncate(attacker.geo?.countryCode || "??", 8).padEnd(8),
          attacker.intent.padEnd(13),
          attacker.risk.padEnd(8),
          String(attacker.totalScore).padEnd(5),
          truncate(Object.keys(attacker.services).join(","), 22).padEnd(22),
          attacker.lastSeenAt,
        ])
      );
      const lastEvent = attacker.recentEvents[attacker.recentEvents.length - 1];
      if (lastEvent) console.log(`  ${truncate(lastEvent, 120)}`);
    }
  }

  renderFooter(message);
}

async function renderControls(message = "") {
  const control = await readControlState();

  renderHeader("Controls");
  console.log(`Default action: ${control.defaultAction}`);
  console.log("");
  console.log("Overrides:");

  const overrides = Object.entries(control.sessionActions).sort(([left], [right]) => left.localeCompare(right));
  if (overrides.length === 0) {
    console.log("No per-session overrides.");
  } else {
    for (const [sessionId, action] of overrides.slice(0, 20)) {
      console.log(`${truncate(sessionId, 24).padEnd(24)} | ${action}`);
    }
  }

  renderFooter(message);
}

async function renderProfiles(message = "") {
  const profiles = listServiceProfiles();

  renderHeader("Profiles");
  console.log(line([
    "service".padEnd(10),
    "product".padEnd(30),
    "host".padEnd(30),
    "ports".padEnd(10),
    "tags",
  ]));
  console.log("-".repeat(120));

  for (const profile of profiles) {
    console.log(
      line([
        truncate(profile.service, 10).padEnd(10),
        truncate(`${profile.product} ${profile.version}`, 30).padEnd(30),
        truncate(profile.host, 30).padEnd(30),
        truncate(profile.ports.join(","), 10).padEnd(10),
        truncate(profile.tags.join(","), 32),
      ])
    );
  }

  renderFooter(message);
}

async function renderPersonas(message = "") {
  const personas = listPersonas();

  renderHeader("Personas");
  console.log(line([
    "persona".padEnd(28),
    "group".padEnd(18),
    "host".padEnd(30),
    "services",
  ]));
  console.log("-".repeat(120));

  for (const persona of personas) {
    console.log(
      line([
        truncate(persona.id, 28).padEnd(28),
        persona.group.padEnd(18),
        truncate(persona.host, 30).padEnd(30),
        truncate(Object.keys(persona.services).join(","), 28),
      ])
    );
  }

  renderFooter(message);
}

async function renderDetail(sessionId: string, message = "") {
  const [sessions, transcripts] = await Promise.all([readSessionSnapshots(), readTranscripts()]);
  const session = sessions.find((entry) => entry.id === sessionId);

  renderHeader("Session Detail");
  if (!session) {
    console.log(`Session ${sessionId} not found.`);
    renderFooter(message);
    return;
  }

  console.log(`Session: ${session.id}`);
  console.log(`Service: ${session.service}`);
  console.log(`IP: ${session.ip}`);
  console.log(`Intent: ${session.intent || "unknown"}`);
  console.log(`Score: ${session.score ?? 0}`);
  console.log(`Persona: ${session.personaId || "n/a"}`);
  console.log(`Action: ${session.currentAction}`);
  console.log(`Status: ${session.status}`);
  console.log(`First Seen: ${session.firstSeenAt}`);
  console.log(`Last Seen: ${session.lastSeenAt}`);
  console.log("");
  console.log("Metadata:");
  console.log(JSON.stringify(session.metadata || {}, null, 2));
  console.log("");
  console.log("Events:");
  for (const event of session.events.slice(-10)) {
    console.log(`- ${event}`);
  }

  const relatedTranscripts = transcripts.filter((t) => t.sessionId === sessionId).slice(-3);
  if (relatedTranscripts.length > 0) {
    console.log("");
    console.log("Recent Transcript:");
    for (const transcript of relatedTranscripts) {
      console.log(`  Request:  ${truncate(transcript.request, 160)}`);
      console.log(`  Response: ${truncate(transcript.response, 160)}`);
    }
  }

  renderFooter(message);
}

async function renderAttackerDetail(attackerId: string, message = "") {
  renderHeader("Attacker Profile");

  const attacker = await getAttackerById(attackerId);
  if (!attacker) {
    console.log(`Attacker ${attackerId} not found. Use the full fingerprint ID.`);
    renderFooter(message);
    return;
  }

  console.log(`ID:        ${attacker.id}`);
  console.log(`Source IP: ${attacker.sourceIp}`);
  if (attacker.geo) {
    console.log(`Location:  ${attacker.geo.city}, ${attacker.geo.country} (${attacker.geo.countryCode})`);
    console.log(`ISP/ASN:   ${attacker.geo.isp} / ${attacker.geo.asn}`);
  }
  console.log(`Risk:      ${attacker.risk}`);
  console.log(`Intent:    ${attacker.intent}`);
  console.log(`Score:     ${attacker.totalScore}`);
  console.log(`First Seen: ${attacker.firstSeenAt}`);
  console.log(`Last Seen:  ${attacker.lastSeenAt}`);
  console.log("");
  console.log("Intent Counts:");
  for (const [intent, count] of Object.entries(attacker.intentCounts)) {
    console.log(`  ${intent.padEnd(14)} ${count}`);
  }
  console.log("");
  console.log("Counters:");
  console.log(`  connections   ${attacker.counters.connections}`);
  console.log(`  auth attempts ${attacker.counters.authAttempts}`);
  console.log(`  commands      ${attacker.counters.commands}`);
  console.log(`  uploads       ${attacker.counters.uploads}`);
  console.log("");
  console.log("Services Touched:");
  for (const [service, memory] of Object.entries(attacker.services)) {
    if (!memory) continue;
    console.log(`  ${service.padEnd(10)} persona=${memory.personaId}  host=${memory.host}`);
    if (memory.usernames.length > 0) {
      console.log(`             usernames: ${memory.usernames.join(", ")}`);
    }
    if (memory.commandHistory.length > 0) {
      console.log(`             last cmds: ${memory.commandHistory.slice(-3).join(" | ")}`);
    }
  }
  console.log("");
  console.log("Recent Events (last 10):");
  for (const event of attacker.recentEvents.slice(-10)) {
    console.log(`  ${truncate(event, 110)}`);
  }

  renderFooter(message);
}

async function renderReplay(sessionId: string, message = "") {
  renderHeader(`Transcript Replay: ${sessionId}`);

  const transcripts = await readTranscripts();
  const related = transcripts.filter((t) => t.sessionId === sessionId);

  if (related.length === 0) {
    console.log(`No transcript entries found for session ${sessionId}.`);
    renderFooter(message);
    return;
  }

  console.log(`${related.length} transcript entries  service=${related[0].service}  ip=${related[0].sourceIp}`);
  console.log("");

  for (const entry of related) {
    console.log(`[${entry.at}] intent=${entry.intent} score=${entry.score} action=${entry.action}`);
    if (entry.request) {
      console.log(`  >> ${truncate(entry.request, 140)}`);
    }
    if (entry.response) {
      console.log(`  << ${truncate(entry.response, 140)}`);
    }
    console.log("");
  }

  renderFooter(message);
}

async function renderScreen(view: ViewState, message = "") {
  if (process.stdout.isTTY) {
    process.stdout.write("\x1Bc");
  }

  switch (view.mode) {
    case "menu":
      await renderMenu(message);
      return;
    case "attackers":
      await renderAttackers(message);
      return;
    case "controls":
      await renderControls(message);
      return;
    case "profiles":
      await renderProfiles(message);
      return;
    case "personas":
      await renderPersonas(message);
      return;
    case "detail":
      await renderDetail(view.sessionId, message);
      return;
    case "attacker":
      await renderAttackerDetail(view.attackerId, message);
      return;
    case "replay":
      await renderReplay(view.sessionId, message);
      return;
    case "sessions":
    default:
      await renderSessions(message);
  }
}

function getViewForCommand(command?: string): ViewState | null {
  switch (command) {
    case "menu":
    case "m":
    case "home":
      return { mode: "menu" };
    case "1":
    case "sessions":
      return { mode: "sessions" };
    case "2":
    case "attackers":
      return { mode: "attackers" };
    case "3":
    case "controls":
    case "control":
      return { mode: "controls" };
    case "4":
    case "profiles":
      return { mode: "profiles" };
    case "5":
    case "personas":
      return { mode: "personas" };
    default:
      return null;
  }
}

export async function runWatchMode(options: WatchModeOptions = {}) {
  const interactive = Boolean(process.stdin.isTTY && process.stdout.isTTY);
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: interactive,
  });

  let lastMessage = options.message || "";
  let closed = false;
  let view: ViewState = options.initialView || { mode: "menu" };

  process.stdin.on("end", () => {
    if (!closed) {
      closed = true;
      clearInterval(timer);
      rl.close();
    }
  });

  // Only auto-refresh when a human is watching
  const timer = setInterval(() => {
    if (!closed && interactive) {
      void renderScreen(view, lastMessage);
    }
  }, 2000);

  await renderScreen(view, lastMessage);
  if (interactive) {
    rl.setPrompt("> ");
    rl.prompt();
  }

  rl.on("line", async (input) => {
    const trimmed = input.trim();
    const [command, arg1, arg2] = trimmed.split(/\s+/);
    const targetView = getViewForCommand(command);

    try {
      if (!trimmed || command === "refresh") {
        lastMessage = "";
      } else if (command === "help") {
        lastMessage = "Commands are listed below.";
      } else if (targetView) {
        view = targetView;
        lastMessage = "";
      } else if (command === "show" && arg1) {
        view = { mode: "detail", sessionId: arg1 };
        lastMessage = "";
      } else if (command === "attacker" && arg1) {
        view = { mode: "attacker", attackerId: arg1 };
        lastMessage = "";
      } else if (command === "replay" && arg1) {
        view = { mode: "replay", sessionId: arg1 };
        lastMessage = "";
      } else if (command === "default" && arg1 && isValidAction(arg1)) {
        await setDefaultAction(arg1);
        lastMessage = `Default action set to ${arg1}`;
      } else if (command === "set" && arg1 && arg2 && isValidAction(arg2)) {
        await setSessionAction(arg1, arg2);
        lastMessage = `Session ${arg1} action set to ${arg2}`;
      } else if (command === "quit" || command === "exit" || command === "q") {
        closed = true;
        clearInterval(timer);
        rl.close();
        return;
      } else {
        lastMessage = "Invalid command. Type `help`.";
      }
    } catch (error) {
      lastMessage = `Command failed: ${String(error)}`;
    }

    if (!closed) {
      await renderScreen(view, lastMessage);
      if (interactive) {
        rl.prompt();
      }
    }
  });

  rl.on("close", () => {
    closed = true;
    clearInterval(timer);
    process.exit(0);
  });
}
