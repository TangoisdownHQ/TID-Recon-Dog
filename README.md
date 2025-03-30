# 🛡️ TID-Recon-Dog: AI-Powered Decoy Honeypot

## 📌 Introduction

TID-Recon-Dog is a **deceptive honeypot system** designed to lure and log malicious actors while simulating real-world services such as **HTTP, SSH, FTP, and PostgreSQL**. The system integrates **AI-powered agents** (via LangChain & GPT4All) to generate realistic responses and analyze attack patterns.

## 🚀 Features

- **Decoy Services**: HTTP, SSH, FTP, and PostgreSQL honeypots
    
- **AI-Powered Responses**: Fake service replies via local AI models (Mistral, GPT4All)
    
- **Logging & Analysis**: Captures attacker IPs, authentication attempts, and commands
    
- **Dockerized Deployment**: Easy setup via `docker-compose`
    
- **Rate Limiting & Obfuscation**: Protect against mass scans & automated attacks
    
- **Configurable Services**: Modify environment variables to adjust behavior
    

---

## 📂 Project Structure

```
TID-Recon-Dog/
│── dist/                 # Compiled TypeScript output
│── logs/                 # Stored logs from interactions
│── models/               # AI models (Mistral, GPT4All)
│── src/
│   ├── services/
│   │   ├── httpService.ts  # HTTP honeypot
│   │   ├── sshService.ts   # SSH honeypot
│   │   ├── ftpService.ts   # FTP honeypot                        } ## Markers Indicate update in new versiont in v2
│   │   ├── pgService.ts    # PostgreSQL honeypot                 }
│   ├── ai/
│   │   ├── aiAgent.ts      # AI response engine                  }
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
```

---

## 🛠️ Installation

### **1️⃣ Clone the Repository**

```
git clone https://github.com/TangoisdownHQ/TID-Recon-Dog.git
cd TID-Recon-Dog
```

### **2️⃣ Install Dependencies**

```
npm install
```

### **3️⃣ Build the TypeScript Code**

```
npx tsc
```

### **4️⃣ Start the Services**

```
node dist/index.js
```

---

## 🐳 Docker Deployment

### **1️⃣ Build & Run with Docker Compose**

```
docker-compose up -d --build
```

### **2️⃣ Check Running Containers**

```
docker ps
```

### **3️⃣ View Live Logs**

```
docker logs -f tid-recon-dog
```

### **4️⃣ Stop & Remove Containers**

```
docker-compose down
```

---

## 📡 Testing the Honeypot

### **HTTP Service**

```
curl http://localhost:3000/api/v1/users
```

### **SSH Service**

```
ssh honeypot@localhost -p 2222
```

### **FTP Service**

```
ftp localhost 21
```

### **PostgreSQL Service**

```
psql -h localhost -p 5432 -U honeypot -d honeypot_logs
```

---

## 🧠 AI-Powered Interactions

The honeypot integrates **local AI models** to generate realistic responses. It supports:

- **Mistral 7B**
    
- **GPT4All**
    
- **LLaMA-based models**
    

#### **Running the AI Agent**

```
node dist/ai/aiAgent.js
```

#### **Modify AI Model in** `**config.ts**`

```
const AI_MODEL_PATH = "./models/mistral-7b.Q4_0.gguf";
```

---

## 📜 Logs & Analysis

All interactions are logged in `**logs/connections.log**`.

#### **View Logs Live**

```
tail -f logs/connections.log
```

#### **Example Log Entry**

```
[2025-02-26T02:03:11.621Z] HTTP - IP: 127.0.0.1 - Path: /login - User-Agent: Mozilla/5.0 - Referrer: none
[2025-02-26T02:03:12.650Z] SSH - IP: 192.168.1.12 - Authentication attempt: root/password123
```

---

## 🔥 Advanced Features

✅ **Rate Limiting & IP Banning**

- Modify `config.ts` to set max requests
    

✅ **Custom AI Responses**

- Extend `aiAgent.ts` for more realistic AI-generated replies
    

✅ **Dynamic Route Names**

- Every HTTP endpoint is randomized
    

✅ **Session Expiry for SSH & FTP**

- Attackers are automatically logged out after a delay
    

---

## 🎯 Future Plans

✅ **Machine Learning-based Attack Detection** ✅ **Integration with SIEM tools (Splunk, ELK)** ✅ **More Deceptive Services (SMB, RDP)** ✅ **Automated Threat Intelligence Reporting**

✅ **
---

## 🤝 Contributing

Want to help improve **TID-Recon-Dog**?

. Open a pull request
    

---

## 🛡️ Disclaimer

**TID-Recon-Dog is a security research tool.** It is intended for legal use **only** and must be deployed with proper authorization. Unauthorized deployment may violate cybersecurity laws.

---

## 📩 Contact & Support

**GitHub Issues:** [Create an issue](https://github.com/yourusername/TID-Recon-Dog/issues) **Email:** support@yourdomain.com

---
