import fs from "fs/promises";
import path from "path";
import { config } from "../config/config.js";
import { readTranscripts } from "../deception_engine/logging/transcript_store.js";
import { listAttackers } from "../deception_engine/state/attacker_memory.js";
import { readControlState } from "../operator/controlPlane.js";
import { readLogEntries, readSessionSnapshots } from "../utils/logger.js";

function toJsonl(records: unknown[]) {
  if (records.length === 0) {
    return "";
  }
  return `${records.map((record) => JSON.stringify(record)).join("\n")}\n`;
}

function buildTaskDefinition() {
  const ports = [
    config.services.http.port,
    config.services.ssh.port,
    config.services.ftp.port,
    config.services.postgres.port,
    config.services.rtsp.port,
    config.services.rdp.port,
    config.services.telnet.port,
    config.services.modbus.port,
  ];

  return {
    family: "tid-recon-dog",
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    cpu: "1024",
    memory: "2048",
    executionRoleArn: "arn:aws:iam::<account-id>:role/ecsTaskExecutionRole",
    taskRoleArn: "arn:aws:iam::<account-id>:role/tidReconDogTaskRole",
    containerDefinitions: [
      {
        name: "tid-recon-dog",
        image: "<account-id>.dkr.ecr.<region>.amazonaws.com/tid-recon-dog:latest",
        essential: true,
        command: ["node", "dist/index.js", "start", "all"],
        portMappings: ports.map((port) => ({
          containerPort: port,
          hostPort: port,
          protocol: port === config.services.http.port ? "tcp" : "tcp",
        })),
        healthCheck: {
          command: ["CMD-SHELL", "wget -qO- http://127.0.0.1:3000/healthz >/dev/null || exit 1"],
          interval: 30,
          timeout: 5,
          retries: 3,
          startPeriod: 20,
        },
        environment: [
          { name: "HTTP_PORT", value: String(config.services.http.port) },
          { name: "SSH_PORT", value: String(config.services.ssh.port) },
          { name: "FTP_PORT", value: String(config.services.ftp.port) },
          { name: "POSTGRES_PORT", value: String(config.services.postgres.port) },
          { name: "RTSP_PORT", value: String(config.services.rtsp.port) },
          { name: "RDP_PORT", value: String(config.services.rdp.port) },
          { name: "TELNET_PORT", value: String(config.services.telnet.port) },
          { name: "MODBUS_PORT", value: String(config.services.modbus.port) },
        ],
        mountPoints: [
          {
            sourceVolume: "runtime-data",
            containerPath: "/app/runtime",
            readOnly: false,
          },
        ],
        logConfiguration: {
          logDriver: "awslogs",
          options: {
            "awslogs-group": "/ecs/tid-recon-dog",
            "awslogs-region": "<region>",
            "awslogs-stream-prefix": "service",
          },
        },
      },
    ],
    volumes: [
      {
        name: "runtime-data",
      },
    ],
  };
}

function buildCloudReadme() {
  return [
    "# TID-Recon-Dog Cloud Bundle",
    "",
    "This bundle packages runtime artifacts for later ingestion into S3, SQS, Kinesis, and ECS/Fargate.",
    "",
    "Directories:",
    "- `s3/`: structured logs, sessions, attackers, transcripts, and control state for archive upload.",
    "- `sqs/`: JSONL message envelopes ready for an SQS publisher.",
    "- `kinesis/`: JSONL records with partition keys and base64 payloads.",
    "- `ecs/`: Fargate task definition and deployment notes.",
  ].join("\n");
}

export async function exportCloudBundle(outputDir?: string) {
  const [logs, sessions, attackers, transcripts, control] = await Promise.all([
    readLogEntries(),
    readSessionSnapshots(),
    listAttackers(),
    readTranscripts(),
    readControlState(),
  ]);

  const baseDir = outputDir
    ? path.resolve(outputDir)
    : path.resolve("exports", `cloud-bundle-${new Date().toISOString().replace(/[:.]/g, "-")}`);

  const s3Dir = path.join(baseDir, "s3");
  const sqsDir = path.join(baseDir, "sqs");
  const kinesisDir = path.join(baseDir, "kinesis");
  const ecsDir = path.join(baseDir, "ecs");
  await Promise.all([fs.mkdir(s3Dir, { recursive: true }), fs.mkdir(sqsDir, { recursive: true }), fs.mkdir(kinesisDir, { recursive: true }), fs.mkdir(ecsDir, { recursive: true })]);

  await Promise.all([
    fs.writeFile(path.join(baseDir, "README.md"), buildCloudReadme(), "utf8"),
    fs.writeFile(path.join(s3Dir, "logs.jsonl"), toJsonl(logs), "utf8"),
    fs.writeFile(path.join(s3Dir, "transcripts.jsonl"), toJsonl(transcripts), "utf8"),
    fs.writeFile(path.join(s3Dir, "sessions.json"), JSON.stringify(sessions, null, 2), "utf8"),
    fs.writeFile(path.join(s3Dir, "attackers.json"), JSON.stringify(attackers, null, 2), "utf8"),
    fs.writeFile(path.join(s3Dir, "controls.json"), JSON.stringify(control, null, 2), "utf8"),
    fs.writeFile(
      path.join(sqsDir, "messages.jsonl"),
      toJsonl(
        transcripts.map((transcript, index) => ({
          Id: `${index + 1}`,
          MessageGroupId: transcript.service,
          MessageBody: JSON.stringify(transcript),
          MessageAttributes: {
            attacker_id: transcript.attackerId,
            session_id: transcript.sessionId,
            intent: transcript.intent,
          },
        }))
      ),
      "utf8"
    ),
    fs.writeFile(
      path.join(kinesisDir, "records.jsonl"),
      toJsonl(
        [...logs, ...transcripts].map((record, index) => ({
          Sequence: index + 1,
          PartitionKey: String((record as Record<string, unknown>).attackerId || (record as Record<string, unknown>).service || "general"),
          Data: Buffer.from(JSON.stringify(record), "utf8").toString("base64"),
        }))
      ),
      "utf8"
    ),
    fs.writeFile(path.join(ecsDir, "task-definition.json"), JSON.stringify(buildTaskDefinition(), null, 2), "utf8"),
  ]);

  return {
    targetPath: baseDir,
    logs: logs.length,
    sessions: sessions.length,
    attackers: attackers.length,
    transcripts: transcripts.length,
  };
}
