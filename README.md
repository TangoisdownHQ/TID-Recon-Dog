# 🛡️ TID-Recon-Dog: AI-Powered Decoy Honeypot

## 📌 Introduction

**TID-Recon-Dog** is an advanced deception platform built to **trap**, **track**, and **analyze** malicious intrusions using a powerful blend of honeypots and **local AI agents**.

> Simulates real-world services like `SSH`, `HTTP`, `FTP`, and `PostgreSQL`, delivering highly believable responses powered by LLMs (Mistral, TinyLlama, GPT4All).  
> Logs every move an attacker makes — with zero exposure risk.

---

## ✨ Key Features

- 🧠 **AI-Powered Deception**  
  Local LLMs simulate system responses, banners, and output with deceptive realism.

- 🛡️ **Multi-Protocol Honeypots**  
  Simulates SSH, HTTP, FTP, and PostgreSQL with authentic endpoint behavior.

- 🗂️ **File Uploads & Listings**  
  Attackers can interact with fake files and directories.

- 🕵️ **Advanced Logging**  
  IP, headers, auth attempts, uploaded files, and commands — geo-tagged and enriched.

- 📡 **External Ready (DMZ / Edge)**  
  Deploy in any DMZ, network boundary, or deceptive edge.

- 🧱 **Modular & AI-Pluggable**  
  Switch AI models, rotate fake content, and extend new services easily.

---

## 💼 Enterprise & Cloud Use

| Feature                     | Supported |
|----------------------------|-----------|
| 🌐 DMZ / Perimeter Deploy  | ✅         |
| 🐳 Docker / Compose Ready  | ✅         |
| ☁️ Cloud-Native (K8s)      | ✅         |
| 🧠 Local LLMs (Offline)    | ✅         |
| 📊 SIEM Integrations (WIP) | ✅         |

---

## 💡 Use Cases

- Threat Intelligence Gathering  
- Honeynet Deployments  
- Red Team / Blue Team Defense  
- AI/LLM Deception Research  
- Early-Stage Recon / Fingerprinting  
- Endpoint Simulation in Wargames

---

## 📦 Tech Stack

- **Node.js / TypeScript**  
- **LangChain + Mistral, TinyLlama, GPT4All**  
- **Docker / Kubernetes / LM Studio / Ollama**  
- **Pino (Logging), Express.js, FTP-Srv**

---

## 📂 Project Structure


TID-Recon-Dog/
│── dist/                 # Compiled TypeScript output
│── logs/                 # Stored logs from interactions
│── models/               # AI models (Mistral, GPT4All)
│── src/
│   ├── services/
│   │   ├── httpService.ts  # HTTP honeypot
│   │   ├── sshService.ts   # SSH honeypot
│   │   ├── ftpService.ts   # FTP honeypot
│   │   ├── dbService.ts    # PostgreSQL honeypot
│   ├── ai/
│   │   ├── aiAgent.ts      # AI response engine
│   ├── utils/
│   │   ├── logger.ts       # Logging system
│   ├── config/
│   │   ├── config.ts       # Configuration file
│   ├── index.ts            # Entry point
│── docker-compose.yml      # Docker setup
│── Dockerfile              # Docker build instructions
│── package.json            # Dependencies
│── tsconfig.json           # TypeScript settings
│── README.md               # Documentation



---

## 🚀 Getting Started (Local)

### 1. Clone & Install
```bash
git clone https://github.com/TangoisdownHQ/TID-Recon-Dog.git
cd TID-Recon-Dog
npm install

2. Build TypeScript
npx tsc

3. Run Locally
node dist/index.js

🐳 Docker Deployment
docker-compose up --build -d
View logs: docker logs -f tid-recon-dog

Stop: docker-compose down

☁️ Kubernetes Deployment
Deploy TID-Recon-Dog as a microservice in your Kubernetes honeynet cluster.
1. Expose via Ingress / NodePort

🌐 Web-Exposed Services
Service	Port
HTTP	3000
SSH	2222
FTP	2121
PostgreSQL	5432
You can expose them via ngrok, reverse proxy, or Kubernetes ingress.

🧠 AI Response Engine
// src/ai_agents/aiResponder.ts

- Uses Mistral 7B, TinyLlama, or GPT4All
- Dynamically responds with fake shell output, DB logs, system banners
- Never reveals honeypot intent

🧪 Testing
curl http://localhost:3000
curl -X POST http://localhost:3000/upload
ssh fake@localhost -p 2222
ftp localhost
psql -h localhost -p 5432 -U honeypot

🪵 Logs & Threat Analysis
tail -f logs/connections.log

📤 AI Model Configuration
Change model in config.ts or .env:

export const AI_MODEL = "mistral-7b-instruct-v0.3"; // or tinyllama, phi2
To use LM Studio:

Set base URL: http://localhost:1234/v1

Ensure LM Studio is running

Model should support chat-style roles

📈 Future Roadmap
 SMB / RDP Fake Services

 Web Dashboard for Activity

 SIEM Log Forwarding (Elastic / Splunk)

 Real-time AI Threat Scoring

 Alert Webhooks / Email / Slack

 Decoy Container API tokens, Secrets

🔐 Licensing
This project is commercially licensed.

To request a license key, partnership, or enterprise license: 📩 Email: support@yourdomain.com

📣 Contact
🔗 GitHub Issues

✉️ tangoisdown@Tutanota.de

🧪 Test Portal (coming soon)

⚠️ Legal Disclaimer
TID-Recon-Dog is for research and legal defense only.
Do not deploy in environments without proper authorization.
Use at your own risk. Complies with legal deceptive defense strategies under cybersecurity frameworks.

⭐ Like This Project?
Star the repo ⭐
Share with Red Teams 🕵️
Integrate it into your SOC / honeynet 📊

