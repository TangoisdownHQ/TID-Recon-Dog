Upload Volume Information

        ______     __     __     ______
       /\  == \   /\ \   /\ \   /\  ___\
        \ \  __<   \ \ \  \ \ \  \ \  __\
        \ \_\ \_\  \ \_\  \ \_\  \ \_____\
         \/_/ /_/   \/_/   \/_/   \/_____/

    |       T   54    A   41    N   4E    G   47    O   4F    I   49    S   53    
    |       D   44    O   4F    W   57    N   4E    -   2D
    |       R   52    E   45    C   43    O   4F    N   4E    -   2D
    |       D   44    O   4F    G   47

    |                  BRAVE NEW WORLD . .  .  .


    |               𓏺𓏺 𓎆𓎆𓏺𓏺𓏺𓏺𓏺𓏺 𓆼𓆼 𓎆𓎆 𓏺𓏺𓏺𓏺𓏺


  
    Overview
    TID-Recon-Dog is an AI-powered honeypot designed to deceive attackers, log their interactions, and simulate fake services.
    It supports HTTP, SSH, FTP, PostgreSQL, and can be extended for blockchain & space networks.

    This tool is useful for:
    ✅ Threat Intelligence – Understand attacker behavior
    ✅ Cyber Deception – Fake services to trick hackers
    ✅ AI-driven Responses – Uses AI to generate deceptive replies
    ✅ High-Traffic Environments – Optimized for performance

    ⚡ Features
    🔹 Realistic Fake Services – SSH, FTP, HTTP, PostgreSQL & more
    🔹 Dynamic AI Response Engine – Uses LangChain or Local LLMs
    🔹 Rate Limiting & Obfuscation – Prevent easy detection
    🔹 Full Logging & Analysis – Tracks all attacker interactions
    🔹 Modular Design – Easily extend with new services

    🛠 Installation
    1️⃣ Clone the Repository
    sh
    Copy
    git clone https://github.com/TangoisdownHQ/tidrecondog-LOTL-Satelittecolony-282025.git
    cd tidrecondog-LOTL-Satelittecolony-282025
    2️⃣ Install Dependencies
    sh
    Copy
    npm install  
    3️⃣ Build the Project
    sh
    Copy
    npx tsc
    4️⃣ Run the Server
    sh
    Copy
    node dist/index.js
    🔥 Usage
    Start the HTTP Honeypot
    After running the server, test it:

    sh
    Copy
    curl http://localhost:3000/api/v1/users
    The request will timeout or return randomized errors.

    Start the SSH Honeypot
    Try connecting via SSH:

    sh
    Copy
    ssh attacker@localhost -p 2222
    It will log the attacker's attempts but always fail authentication.

    🔧 Configuration
    Modify config/config.ts to adjust:

    Port Numbers for HTTP, SSH, FTP, PostgreSQL
    Logging Behavior (File-based or Cloud-based)
    AI Response Behavior
    📜 Logs & Analysis
    View live logs:

    sh
    Copy
    tail -f logs/connections.log
    Example Log:

    yaml
    Copy
    [2025-02-26T12:34:56Z] SSH - IP: 192.168.1.100 - Authentication attempt: Username: admin, Password: root
    🔮 Future Enhancements
    🚀 AI-powered Deception – Using LangChain & LLMs
    🛰 Integration with Satellite & Blockchain Networks
    🎭 More Realistic Service Simulation




First upload was [28-2025 everything is working]
