# Live model inference (shadow / AI modes)

The trained Qwen3-4B can drive live responses, gated by the **Engine Mode** in the
operator Control tab:

| Mode | Behavior |
|------|----------|
| `deterministic` | Hardcoded responders only (default, safe). |
| `shadow` | Serves the deterministic reply, but also asks the model for a candidate and logs both to `runtime/shadow.jsonl` (review in the MLOps tab / `GET /api/shadow`). The attacker never sees the model. |
| `ai` | When a session's action is `decoy_success`, the model writes the served response (sanitized via `safety.ts`); falls back to deterministic on any model error. |

Wired into the SSH `exec` + interactive shell today (`src/responders/aiEngine.ts`).
If `AI_MODEL_URL` is unset, shadow/ai silently fall back to deterministic.

## Point it at a model server (OpenAI-compatible)

Any OpenAI-compatible `/v1/chat/completions` endpoint works — llama.cpp's
`llama-server`, Ollama, vLLM, or a Bedrock proxy.

```sh
# Env on the honeypot:
AI_MODEL_URL=http://127.0.0.1:8080/v1/chat/completions
AI_MODEL=honeypot-qwen
AI_API_KEY=            # if the endpoint needs one
AI_TIMEOUT_MS=12000
AI_MAX_TOKENS=256
```

### Option A — llama.cpp server (uses the GGUF directly)

```sh
cd mlops/llama_cpp && cmake -B build && cmake --build build -j   # one-time build
./build/bin/llama-server -m ../Qwen3-4B-Base-Q8.gguf --host 127.0.0.1 --port 8080 -c 4096
# honeypot: AI_MODEL_URL=http://127.0.0.1:8080/v1/chat/completions
```

### Option B — Ollama

```sh
ollama create honeypot-qwen -f Modelfile     # Modelfile FROM ../Qwen3-4B-Base-Q8.gguf
ollama serve
# honeypot: AI_MODEL_URL=http://127.0.0.1:11434/v1/chat/completions  AI_MODEL=honeypot-qwen
```

## Deployment note (hardware)

The 4 GB Q8 model needs real resources:
- **Does NOT fit** the current `t3.small` (2 GB). Enabling AI there is a no-op.
- **CPU** (`t3.xlarge`+, 16 GB): works but slow (seconds–tens of seconds per reply) — fine for shadow review, too slow for a believable live shell.
- **GPU** (`g5.xlarge`): fast, realistic latency — the right choice for live `ai` mode.

Recommended rollout: deploy with AI **off**, run the model server beside it,
switch to **shadow** to vet quality, then flip to **ai** once you trust it.
Run the model as a sidecar container (compose) or a separate Deployment + GPU
node group on EKS (`k8s/mlops/`).
