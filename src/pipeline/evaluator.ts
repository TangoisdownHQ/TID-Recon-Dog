import fs from "fs/promises";
import path from "path";
import { listServiceProfiles } from "../profiles/serviceProfiles.js";

type EvalCase = {
  id: string;
  service: string;
  prompt: string;
  expected_keywords: string[];
  forbidden_keywords: string[];
  protocol_pattern: string;
  banner_fragment: string;
};

type EvalResponse = {
  id: string;
  response: string;
};

type EvalScore = {
  id: string;
  service: string;
  passed: boolean;
  score: number;
  checks: {
    protocol_match: boolean;
    banner_match: boolean;
    expected_keywords: number;
    forbidden_keywords: string[];
  };
};

function buildEvalCases(): EvalCase[] {
  return listServiceProfiles().map((profile) => {
    const service = profile.service.toUpperCase();

    if (service === "RTSP") {
      return {
        id: "rtsp_describe_auth",
        service,
        prompt: `Emulate an RTSP relay. Client sent DESCRIBE rtsp://${profile.host}:${profile.ports[0]}/Streaming/Channels/401 without authorization. Reply with a single realistic protocol response.`,
        expected_keywords: ["RTSP/1.0", "401", "WWW-Authenticate", profile.realm],
        forbidden_keywords: ["honeypot", "decoy", "simulation", "testing", "ai"],
        protocol_pattern: "^RTSP/1\\.0\\s+\\d{3}",
        banner_fragment: "Server:",
      };
    }

    if (service === "RDP") {
      return {
        id: "rdp_preauth_banner",
        service,
        prompt: `Emulate a Windows jump host preauth negotiation failure for ${profile.host}. Return a terse low-level response or banner fragment only.`,
        expected_keywords: ["Cookie", "mstshash"],
        forbidden_keywords: ["honeypot", "decoy", "simulation", "testing", "ai"],
        protocol_pattern: "Cookie:\\s*mstshash=",
        banner_fragment: "mstshash",
      };
    }

    if (service === "TELNET") {
      return {
        id: "telnet_login_prompt",
        service,
        prompt: `Emulate a BusyBox telnet login prompt for ${profile.host}. Return only what the client should see.`,
        expected_keywords: ["login", profile.host.split(".")[0]],
        forbidden_keywords: ["honeypot", "decoy", "simulation", "testing", "ai"],
        protocol_pattern: "login:",
        banner_fragment: "login:",
      };
    }

    if (service === "MODBUS") {
      return {
        id: "modbus_status",
        service,
        prompt: `Emulate a Modbus TCP status response for unit 1 on ${profile.host}. Return a terse industrial controller status line.`,
        expected_keywords: ["unit", "1", "online"],
        forbidden_keywords: ["honeypot", "decoy", "simulation", "testing", "ai"],
        protocol_pattern: "(unit|register|MBTCP)",
        banner_fragment: "unit",
      };
    }

    if (service === "SSH") {
      return {
        id: "ssh_banner",
        service,
        prompt: `Emulate an SSH server banner for ${profile.host}. Return the raw banner only.`,
        expected_keywords: ["SSH-2.0", "OpenSSH"],
        forbidden_keywords: ["honeypot", "decoy", "simulation", "testing", "ai"],
        protocol_pattern: "^SSH-2\\.0-",
        banner_fragment: "OpenSSH",
      };
    }

    if (service === "FTP") {
      return {
        id: "ftp_banner",
        service,
        prompt: `Emulate an FTP service banner for ${profile.host}. Return the raw banner only.`,
        expected_keywords: ["220", "FTP"],
        forbidden_keywords: ["honeypot", "decoy", "simulation", "testing", "ai"],
        protocol_pattern: "^220",
        banner_fragment: "220",
      };
    }

    if (service === "POSTGRES") {
      return {
        id: "postgres_auth_failure",
        service,
        prompt: `Emulate a PostgreSQL authentication failure for ${profile.host}. Return a single realistic server error line.`,
        expected_keywords: ["FATAL", "password", "user"],
        forbidden_keywords: ["honeypot", "decoy", "simulation", "testing", "ai"],
        protocol_pattern: "FATAL:",
        banner_fragment: "FATAL",
      };
    }

    return {
      id: `${service.toLowerCase()}_generic`,
      service,
      prompt: `Emulate ${profile.displayName} on ${profile.host}. Return a short technical response consistent with ${profile.product} ${profile.version}.`,
      expected_keywords: [profile.product.split(" ")[0]],
      forbidden_keywords: ["honeypot", "decoy", "simulation", "testing", "ai"],
      protocol_pattern: ".+",
      banner_fragment: profile.product.split(" ")[0],
    };
  });
}

export async function exportEvalSuite(outputPath?: string) {
  const evalDir = path.resolve("ct", "eval");
  await fs.mkdir(evalDir, { recursive: true });
  const targetPath = path.resolve(outputPath || path.join(evalDir, "suite.jsonl"));
  await fs.mkdir(path.dirname(targetPath), { recursive: true });

  const cases = buildEvalCases();
  const jsonl = cases.map((record) => JSON.stringify(record)).join("\n");
  await fs.writeFile(targetPath, `${jsonl}\n`, "utf8");

  return {
    targetPath,
    cases: cases.length,
  };
}

function containsForbidden(response: string, forbidden: string[]) {
  return forbidden.filter((word) => {
    const pattern = new RegExp(`\\b${word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");
    return pattern.test(response);
  });
}

function countExpected(response: string, expected: string[]) {
  const lower = response.toLowerCase();
  return expected.reduce((count, word) => count + (lower.includes(word.toLowerCase()) ? 1 : 0), 0);
}

export async function scoreEvalResponses(responsePath: string, suitePath?: string, outputPath?: string) {
  const resolvedSuitePath = path.resolve(suitePath || path.join("ct", "eval", "suite.jsonl"));
  const resolvedResponsePath = path.resolve(responsePath);
  const suiteLines = (await fs.readFile(resolvedSuitePath, "utf8"))
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const responseLines = (await fs.readFile(resolvedResponsePath, "utf8"))
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  const suite = new Map<string, EvalCase>(
    suiteLines.map((line) => {
      const parsed = JSON.parse(line) as EvalCase;
      return [parsed.id, parsed];
    })
  );
  const responses = responseLines.map((line) => JSON.parse(line) as EvalResponse);

  const scores: EvalScore[] = responses
    .map((response) => {
      const testCase = suite.get(response.id);
      if (!testCase) {
        return undefined;
      }

      const protocolMatch = new RegExp(testCase.protocol_pattern, "i").test(response.response);
      const bannerMatch = response.response.toLowerCase().includes(testCase.banner_fragment.toLowerCase());
      const expectedCount = countExpected(response.response, testCase.expected_keywords);
      const forbiddenHits = containsForbidden(response.response, testCase.forbidden_keywords);
      const score =
        (protocolMatch ? 0.35 : 0) +
        (bannerMatch ? 0.25 : 0) +
        Math.min(expectedCount / Math.max(testCase.expected_keywords.length, 1), 1) * 0.3 +
        (forbiddenHits.length === 0 ? 0.1 : 0);

      return {
        id: testCase.id,
        service: testCase.service,
        passed: score >= 0.8,
        score: Number(score.toFixed(3)),
        checks: {
          protocol_match: protocolMatch,
          banner_match: bannerMatch,
          expected_keywords: expectedCount,
          forbidden_keywords: forbiddenHits,
        },
      } satisfies EvalScore;
    })
    .filter((score): score is EvalScore => Boolean(score));

  const summary = {
    generated_at: new Date().toISOString(),
    suite_path: resolvedSuitePath,
    response_path: resolvedResponsePath,
    total_cases: scores.length,
    passed_cases: scores.filter((score) => score.passed).length,
    average_score: scores.length
      ? Number((scores.reduce((sum, score) => sum + score.score, 0) / scores.length).toFixed(3))
      : 0,
    scores,
  };

  const targetPath = path.resolve(outputPath || path.join("ct", "eval", "latest-score.json"));
  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  await fs.writeFile(targetPath, JSON.stringify(summary, null, 2), "utf8");

  return {
    targetPath,
    summary,
  };
}
