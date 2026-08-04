#!/usr/bin/env python3
"""Quarantine training-poisoning attempts out of a transcripts.jsonl before it
reaches the fine-tuner.

The honeypot trains a model to *emulate* its personas from request -> response
pairs. But the request is attacker-controlled, and many responders reflect input
into the response, so an attacker who suspects a honeypot can craft traffic that,
if trained on, teaches the model to break character or mis-behave. The Rust
pipeline dedupes and has a quality gate, but neither defends against *deliberate*
poisoning. This pass does.

Poisoned records are QUARANTINED, not dropped — they are themselves useful intel
(a source probing for an AI backend), so they go to a sidecar file for the CTI
side while being kept out of training.

Checks (each tagged in the quarantine record's `_reasons`):
  break_char_target  response contains meta/AI/reveal phrases (the worst case:
                     training would teach the model to say them). Quarantine.
  injection_input    request looks like a prompt-injection / instruction
                     ("ignore previous", "you are an AI", "system:"). Quarantine.
  oversized          request or response exceeds MAX_FIELD_CHARS (flood/padding).
  control_chars      response is mostly non-printable / ANSI-escape noise.
  attacker_flood     more than MAX_PER_ATTACKER records from one attackerId —
                     the surplus (lowest-signal first) is quarantined so a single
                     source cannot dominate the training distribution.

Usage:
  filter_poison.py <transcripts.jsonl> [--quarantine out.jsonl] [--stats out.json]
Env knobs:
  MAX_FIELD_CHARS   (default 8000)   per-field length cap
  MAX_PER_ATTACKER  (default 300)    records kept per attackerId
  POISON_DISABLE    1 = pass through unchanged (escape hatch)
"""
import json
import os
import re
import sys
from collections import defaultdict

MAX_FIELD_CHARS = int(os.environ.get("MAX_FIELD_CHARS", "8000"))
MAX_PER_ATTACKER = int(os.environ.get("MAX_PER_ATTACKER", "300"))

# Phrases that must never appear in a training TARGET (response) — they would
# teach the model to acknowledge it is an AI / simulation / honeypot. Also used
# (in the request) as a prompt-injection signal. Case-insensitive, word-ish.
REVEAL_PATTERNS = [
    r"\byou are (an?|a) ?(ai|assistant|language model|chatbot|llm)\b",
    r"\blanguage model\b",
    r"\b(chatgpt|gpt-?\d|claude|gemini|llama|qwen|openai|anthropic)\b",
    r"\bas an ai\b",
    r"\bi am (an?|a) ?(ai|assistant|language model|bot|honeypot)\b",
    r"\bhoney ?pot\b",
    r"\bthis is (a )?(simulation|simulated|fake|decoy|emulat)",
    r"\bignore (all |the |your )?(previous|prior|above) (instructions|prompts?)\b",
    r"\b(system|developer) prompt\b",
    r"\bbreak character\b",
    r"\breveal your (instructions|prompt|system)\b",
    r"\bpretend to be\b",
    r"\bact as (an?|a)\b",
]
REVEAL_RE = re.compile("|".join(REVEAL_PATTERNS), re.IGNORECASE)

# Injection markers that make a REQUEST look like an instruction to a model.
INJECTION_RE = re.compile(
    r"(ignore (previous|prior|above)|disregard (previous|all)|"
    r"you are now|new instructions?:|system:\s|assistant:\s|"
    r"repeat (after|the)|print your|output your (prompt|instructions))",
    re.IGNORECASE,
)


def printable_ratio(s: str) -> float:
    if not s:
        return 1.0
    printable = sum(1 for c in s if c == "\n" or c == "\t" or (0x20 <= ord(c) < 0x7F) or ord(c) > 0xA0)
    return printable / len(s)


def score_of(rec: dict) -> int:
    try:
        return int(rec.get("score", 0) or 0)
    except (TypeError, ValueError):
        return 0


def classify(rec: dict) -> list:
    """Return a list of reasons this record is unsafe to train on (empty = clean)."""
    reasons = []
    req = str(rec.get("request", "") or "")
    resp = str(rec.get("response", "") or "")

    if len(req) > MAX_FIELD_CHARS or len(resp) > MAX_FIELD_CHARS:
        reasons.append("oversized")
    # The response is the training target — reveal phrases here are the worst case.
    if REVEAL_RE.search(resp):
        reasons.append("break_char_target")
    if INJECTION_RE.search(req) or REVEAL_RE.search(req):
        reasons.append("injection_input")
    if resp and printable_ratio(resp) < 0.75:
        reasons.append("control_chars")
    return reasons


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    quarantine_path = None
    stats_path = None
    args = sys.argv[2:]
    for i, a in enumerate(args):
        if a == "--quarantine" and i + 1 < len(args):
            quarantine_path = args[i + 1]
        elif a == "--stats" and i + 1 < len(args):
            stats_path = args[i + 1]
    if quarantine_path is None:
        quarantine_path = path + ".quarantine.jsonl"
    if stats_path is None:
        stats_path = path + ".poison-stats.json"

    if os.environ.get("POISON_DISABLE") == "1":
        print("[poison] POISON_DISABLE=1 — passing through unchanged")
        return 0

    try:
        with open(path, "r", errors="ignore") as f:
            raw_lines = [l for l in f if l.strip()]
    except FileNotFoundError:
        print(f"[poison] {path} not found — nothing to filter")
        return 0

    kept, quarantined = [], []
    reason_counts = defaultdict(int)
    malformed = 0

    # First pass: content checks.
    parsed = []
    for line in raw_lines:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        reasons = classify(rec)
        if reasons:
            rec["_reasons"] = reasons
            for r in reasons:
                reason_counts[r] += 1
            quarantined.append(rec)
        else:
            parsed.append(rec)

    # Second pass: per-attacker flood cap on the survivors. Keep the
    # highest-scoring (most intel-bearing) records per attacker; quarantine the
    # surplus so one flooding source can't dominate the training distribution.
    by_attacker = defaultdict(list)
    for rec in parsed:
        by_attacker[str(rec.get("attackerId", "?"))].append(rec)
    for attacker, recs in by_attacker.items():
        if len(recs) <= MAX_PER_ATTACKER:
            kept.extend(recs)
            continue
        recs.sort(key=score_of, reverse=True)
        kept.extend(recs[:MAX_PER_ATTACKER])
        for rec in recs[MAX_PER_ATTACKER:]:
            rec["_reasons"] = ["attacker_flood"]
            reason_counts["attacker_flood"] += 1
            quarantined.append(rec)

    # Write cleaned file in place; write quarantine + stats sidecars.
    with open(path, "w") as f:
        for rec in kept:
            f.write(json.dumps(rec) + "\n")
    if quarantined:
        with open(quarantine_path, "a") as f:  # append: accumulate across runs
            for rec in quarantined:
                f.write(json.dumps(rec) + "\n")

    stats = {
        "input_records": len(raw_lines),
        "malformed": malformed,
        "kept": len(kept),
        "quarantined": len(quarantined),
        "by_reason": dict(reason_counts),
        "max_field_chars": MAX_FIELD_CHARS,
        "max_per_attacker": MAX_PER_ATTACKER,
    }
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)

    pct = (100.0 * len(quarantined) / len(raw_lines)) if raw_lines else 0.0
    print(f"[poison] {len(raw_lines)} in -> {len(kept)} kept, "
          f"{len(quarantined)} quarantined ({pct:.1f}%){' + ' + str(malformed) + ' malformed' if malformed else ''}")
    if reason_counts:
        print("[poison] reasons: " + ", ".join(f"{k}={v}" for k, v in sorted(reason_counts.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
