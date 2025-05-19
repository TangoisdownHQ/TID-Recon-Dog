# 🛡️ TID-Recon-Dog: AI-Powered Decoy Honeypot

![tidrecondog_github_banner](https://github.com/user-attachments/assets/ad46104a-c10f-4c04-85d4-218fe4047784)

TID-Recon-Dog is an advanced deception platform built to trap, track, and analyze malicious intrusions using a powerful blend of honeypots and local AI agents.

**Custom AI Model Hosting (Coming Soon)**  
We will be introducing **RD-AI** — a custom LLM trained specifically for deception & response tactics.

🚧 We are training and hosting our own fine-tuned LLM for deception.
ReconDog-AI will provide advanced, evasive, and intelligent responses across all honeypot services — deployable locally or via API.

You can use our AI LLM model or bring your own — such as Mistral, TinyLLaMA, GPT4All, or any OpenAI-compatible API.

Simulates real-world services like SSH, HTTP, FTP, and PostgreSQL, delivering highly believable responses powered by LLMs.

✨ Key Features
🧠 **AI-Powered Deception**  
Local or remote LLMs simulate system responses, banners, and output with deceptive realism.

🛡️ **Multi-Protocol Honeypots**  
Simulates SSH, HTTP, FTP, and PostgreSQL with authentic endpoint behavior.

🗂️ **File Uploads & Listings**  
Attackers can interact with fake files and directories.

🕵️ **Advanced Logging**  
IP, headers, auth attempts, uploaded files, and commands — geo-tagged and enriched.

📡 **External Ready (DMZ / Edge)**  
Deploy in any DMZ, network boundary, or deceptive edge.

🧱 **Modular & AI-Pluggable**  
Switch AI models, rotate fake content, and extend new services easily.

🌐 **Web App & Server Integration**  
Embed TID-Recon-Dog into existing web applications or public-facing servers to simulate realistic attack surfaces and monitor intrusion attempts.

💼 **Enterprise & Cloud Use**
| Feature                     | Supported |
|-----------------------------|-----------|
| 🌐 DMZ / Perimeter Deploy   | ✅         |
| 🐳 Docker / Compose Ready   | ✅         |
| ☁️ Cloud-Native (K8s)       | ✅         |
| 🧠 Local LLMs (Offline)     | ✅         |
| 📊 SIEM Integrations (WIP)  | ✅         |

💡 **Use Cases**
- Threat Intelligence Gathering
- Honeynet Deployments
- Red Team / Blue Team Defense
- AI/LLM Deception Research
- Early-Stage Recon / Fingerprinting
- Endpoint Simulation in Wargames

📦 **Tech Stack**
- Node.js / TypeScript
- LangChain + Mistral, TinyLLaMA, GPT4All
- Docker / Kubernetes / LM Studio / Ollama
- Pino (Logging), Express.js, FTP-Srv

📂 **Project Structure**
```
TID-Recon-Dog/
├── dist/                 # Compiled TypeScript output
├── logs/                 # Stored logs from interactions
├── models/               # AI models (Mistral, GPT4All)
├── src/
│   ├── services/
│   │   ├── httpService.ts      # HTTP honeypot
│   │   ├── sshService.ts       # SSH honeypot
│   │   ├── ftpService.ts       # FTP honeypot
│   │   ├── pgService.ts        # PostgreSQL honeypot
│   ├── ai/
│   │   ├── aiResponder.ts      # AI response engine
│   ├── utils/
│   │   ├── logger.ts           # Logging system
│   ├── config/
│   │   ├── config.ts           # Configuration file
│   ├── index.ts                # Entry point
├── docker-compose.yml          # Docker setup
├── Dockerfile                  # Docker build instructions
├── package.json                # Dependencies
├── tsconfig.json               # TypeScript settings
├── README.md                   # Documentation
```

---

## 🚀 Getting Started (Local)

### 1. Clone & Install
```bash
git clone https://github.com/TangoisdownHQ/TID-Recon-Dog.git
cd TID-Recon-Dog
npm install
```

### 2. Build TypeScript
```bash
npx tsc
```

### 3. Run Locally
```bash
node dist/index.js
```

---

## 🐳 Docker Deployment
```bash
docker-compose up --build -d
docker logs -f tid-recon-dog
```
To stop:
```bash
docker-compose down
```

---

## ☁️ Kubernetes Deployment
Deploy TID-Recon-Dog as a microservice in your Kubernetes honeynet cluster.
1. Expose services via Ingress or NodePort
2. Configure baseURL for LLM in environment config

---

## 🌐 Web-Exposed Services
| Service     | Port  |
|-------------|-------|
| HTTP        | 3000  |
| SSH         | 2222  |
| FTP         | 2121  |
| PostgreSQL  | 5432  |

Expose these via Ngrok, reverse proxy (Nginx), or Kubernetes ingress.

---

## 🧠 AI Deployment Options
TID-Recon-Dog supports multiple ways to run LLMs:

### 1. Local LLM via LM Studio
- Launch LM Studio
- Load Mistral or TinyLLaMA model
- Update `.env`: `OPENAI_API_BASE=http://localhost:1234/v1`

### 2. Run LLM Locally (Python Backend)
```bash
pip install llama-cpp-python[server]
python -m llama_cpp.server --model ./models/mistral.gguf --port 1234
```

### 3. Remote LLM API (e.g., Together.ai, Groq, OpenRouter)
Set `.env`:
```env
OPENAI_API_BASE=https://api.together.xyz/v1
OPENAI_API_KEY=your_api_key_here
```

### 4. Ollama Backend
```bash
ollama run mistral
```
Set base URL to `http://localhost:11434/v1`

---

## 🧪 Testing
```bash
curl http://localhost:3000
curl -X POST http://localhost:3000/upload
curl -X POST http://localhost:3000/shell -H "Content-Type: application/json" -d '{"cmd":"whoami"}'
ssh fake@localhost -p 2222
ftp localhost
psql -h localhost -p 5432 -U honeypot
```

---

## 🪵 Logs & Threat Analysis
```bash
tail -f logs/connections.log
```

---

## 📈 Future Roadmap
- SMB / RDP Fake Services
- Web Dashboard for Activity
- SIEM Log Forwarding (Elastic / Splunk)
- Real-time AI Threat Scoring
- Alert Webhooks / Email / Slack
- Decoy Container API tokens, Secrets

---

## 🔐 Licensing
This project is commercially licensed.
To request a license key, partnership, or enterprise license:
📩 Email: tangoisdown@Tutanota.de

---

## 📣 Contact
- 🔗 GitHub Issues
- ✉️ tangoisdown@Tutanota.de
- 🧪 Test Portal (coming soon)

⚠️ **Legal Disclaimer**
TID-Recon-Dog is for research and legal defense only.  
Do not deploy in environments without proper authorization.  
Use at your own risk. Complies with legal deceptive defense strategies under cybersecurity frameworks.

---

⭐ **Like This Project?**  
⭐ Star the repo  
🔁 Share with Red Teams  
📊 Integrate it into your SOC / honeynet











