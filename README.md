# Scam Shield 🛡️
### Multilingual AI-Powered Impersonation & Scam Defense System

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Google Gemini](https://img.shields.io/badge/Google_Gemini-2.5_Flash-4285F4?logo=google&logoColor=white)](https://ai.google.dev/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-Streamable_HTTP_2026--07--28-6D28D9)](https://modelcontextprotocol.io/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)

Developed for the **Amazon Developer Hackathon**, **Scam Shield** is a defensive cybersecurity application built to protect consumers across India from sophisticated social engineering, phishing, and fraud campaigns impersonating Amazon.

Scam Shield evaluates suspicious SMS, WhatsApp, and email messages across **English**, **Hindi (हिंदी)**, and **Telugu (తెలుగు)**, pairing deterministic heuristic defense rules with **Google Gemini 2.5 Flash** reasoning.

---

## 🎯 Problem Statement & Threat Landscape

E-commerce impersonation fraud in India is rapidly escalating:
- **Urgent Account Blocking & KYC Threats**: Phishing messages claiming your Amazon account has been suspended or that PAN/Aadhaar re-verification is urgently required.
- **Support & OTP Theft**: Fraudulent customer service agents claiming an order was placed on your card and instructing you to share the 6-digit OTP to cancel it.
- **Failed Delivery Fee Links**: SMS alerts demanding small payments (e.g., ₹25) via malicious or shortened links to reschedule a package.
- **Remote Access Malware**: Scammers instructing consumers to download apps like AnyDesk, QuickSupport, or TeamViewer under the guise of refunds.
- **Festive Lucky Draws**: Deceptive messages promising free iPhones or lottery cash rewards to steal payment card credentials.

Many everyday users cannot distinguish genuine Amazon communications from fraudulent alerts. **Scam Shield** solves this by providing immediate, multilingual, plain-language risk evaluations before users click links, download apps, or share financial credentials.

---

## ✨ Features

- **Interactive AI Voice Assistant**:
  - *Natural Voice Input*: Hands-free microphone button using browser Speech Recognition with real-time text transcription, listening indicators, and graceful permission handling.
  - *Natural Spoken Responses*: Built-in browser Text-to-Speech speaking assistant verdicts aloud in English, Hindi (`hi-IN`), and Telugu (`te-IN`), with audio mute/unmute and instant stop controls.
  - *Empathetic Conversational Companion*: Warmly greets users, answers everyday questions, responds empathetically to boredom/sadness, and explains cyber safety in plain language without pretending to be human.
  - *Context Memory*: Retains session dialogue context across turns.
- **Automatic Scam Link Detection & SSRF Shield**:
  - *Zero-Click Inspection*: Automatically extracts and analyzes all URLs submitted via voice or text.
  - *SSRF Defense*: Validates resolved IP addresses before connecting; strictly blocks `127.0.0.1`, private RFC 1918 networks, link-local metadata (`169.254.169.254`), and non-HTTP/HTTPS protocols.
  - *Hop-by-Hop Redirect Verification*: Inspects every redirect destination's IP before following; aborts unsafe hops.
  - *Lookalike & Typosquatting Detection*: Detects deceptive domain imitations (`amaz0n`, `amzn-security`, `amazon-kyc`, misleading subdomains, and URL shorteners).
  - *Safe Availability Probing*: Probes link reachability safely without downloading full webpages or executing scripts.
- **Multilingual Support**: Tailored detection and localized guidance in **English**, **Hindi (हिंदी)**, and **Telugu (తెలుగు)**.
- **Dual-Engine Security Pipeline**:
  - *Deterministic Rule Engine*: Immediate pattern detection for shortened URLs, KYC extortion, OTP solicitation, UPI collect requests, and remote-access APKs.
  - *Google Gemini AI Enhancement*: Deep contextual evaluation of social engineering, tone, novel tactics, and linguistic nuances.
  - *Risk Score Floor Protection*: AI cannot override or lower a high deterministic rule score, ensuring prompt injection cannot bypass security rules.
- **Model Context Protocol (MCP) Server**: Full Streamable HTTP MCP server exposing both `analyze_scam_message` and `analyze_scam_url` tools for autonomous agents and LLMs.
- **Safe Fallback & Privacy-Preserving Architecture**:
  - Graceful degradation: if Gemini AI is rate-limited or unconfigured, the assistant falls back seamlessly to deterministic rule protection.
  - Messages and links are evaluated locally on your server without storing personally identifiable information (PII).

---

## 🛠️ Technology Stack

| Layer | Technologies |
|---|---|
| **Voice & Speech** | Web Speech API (SpeechRecognition for STT, SpeechSynthesis for TTS), Multi-accent voices (en-IN, hi-IN, te-IN) |
| **Frontend** | Vanilla HTML5, CSS3 (Modern Responsive Design System), JavaScript (ES6+, Text-only XSS-safe DOM rendering) |
| **Backend API** | FastAPI, Pydantic v2, Uvicorn, Python-dotenv, HTTPX (SSRF-guarded link inspector) |
| **AI Integration** | Google GenAI SDK (`google-genai`), Gemini 2.5 Flash |
| **Agent / Protocol** | Model Context Protocol (`mcp[cli] 2.3+`), Streamable HTTP Transport (`analyze_scam_message`, `analyze_scam_url`) |
| **Testing** | Python `unittest`, `httpx`, `fastapi.testclient` (65 automated tests) |

---

## 🏗️ Architecture

```
[ Incoming Message / Voice Speech / Suspicious Link ]
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
  [ Web Browser UI ]     [ MCP Client / Agent ]
  - Web Speech STT/TTS    (Port 8001 /mcp)
  (Port 5500)                    │
         │                       │
         ▼                       ▼
┌───────────────────┐   ┌───────────────────────────┐
│   FastAPI Engine  │   │  Scam Shield MCP Server   │
│   (Port 8000)     │   │  (Streamable HTTP)        │
│   /chat & /analyze│   │  analyze_scam_message     │
│   /analyze-url    │   │  analyze_scam_url         │
└─────────┬─────────┘   └─────────────┬─────────────┘
          │                           │
          ├───────────────────────────┤
          ▼                           ▼
┌───────────────────┐       ┌───────────────────────┐
│ URL & SSRF Engine │       │ Deterministic Rules   │
│ - IP & DNS check  │       │ - Keyword detection   │
│ - SSRF blocklist  │       │ - OTP / KYC / Remote  │
│ - Lookalike brand │       │ - Baseline risk score │
└─────────┬─────────┘       └───────────┬───────────┘
          │                             │
          └──────────────┬──────────────┘
                         ▼
        ┌───────────────────────────────────┐
        │ Google Gemini AI Assistant        │
        │ (google-genai / gemini-2.5-flash) │
        │ - Contextual phishing reasoning   │
        │ - Empathetic conversational chat  │
        │ - Spoken TTS synthesis generator  │
        └─────────────────┬─────────────────┘
                          ▼
        ┌───────────────────────────────────┐
        │ Scored Verdict & Guidance         │
        │ - Final Risk Score (0-100)        │
        │ - Structured Link Report Cards    │
        │ - Localized Translations (hi/te)  │
        └───────────────────────────────────┘
```

---

## 💻 Windows Setup & Installation

### 1. Prerequisites
- Python 3.10+ installed and added to your `PATH`.
- Git installed.

### 2. Clone or Navigate to Project
```powershell
cd scam-sheild
```

### 3. Set Up Python Virtual Environment
```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment in PowerShell
.\.venv\Scripts\Activate.ps1
```

### 4. Install Dependencies
```powershell
pip install -r requirements.txt
```

---

## 🔐 Configuring GEMINI_API_KEY Safely

1. Obtain a free API key from [Google AI Studio](https://aistudio.google.com/).
2. Copy the template configuration file:
   ```powershell
   Copy-Item .env.example .env
   ```
3. Open `.env` and set your key:
   ```env
   GEMINI_API_KEY=your_actual_api_key_here
   GEMINI_MODEL=gemini-2.5-flash
   ```
4. **Security Guarantee**:
   - `.env` is strictly excluded in `.gitignore` and is never committed to version control.
   - The application never displays, logs, or transmits your API key to the client.

---

## 🚀 Running the Services

Open three separate Windows PowerShell windows (with the virtual environment activated in each):

### Terminal 1: FastAPI Backend (Port 8000)
```powershell
python -m uvicorn app.main:app --reload --port 8000
```
- **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- **Interactive OpenAPI Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### Terminal 2: Web Frontend (Port 5500)
```powershell
python -m http.server 5500 --directory frontend
```
- **Open in Browser**: [http://127.0.0.1:5500](http://127.0.0.1:5500)

### Terminal 3: Scam Shield MCP Server (Port 8001)
```powershell
python app/mcp_server.py 8001
```
- **MCP Endpoint**: `http://127.0.0.1:8001/mcp`
- **Transport**: Streamable HTTP
- **Exposed Tool**: `analyze_scam_message`

---

## 🧪 Example Scam Analysis

### Input Message:
> *"Amazon: Your account is blocked due to uncompleted KYC. Update immediately at http://bit.ly/amz-kyc-verify to avoid permanent suspension."*

### API / MCP Tool Output:
```json
{
  "risk_score": 100,
  "verdict": "critical",
  "category": "Fake account-blocking, KYC, or account-verification messages",
  "red_flags": [
    "Threatens account suspension, block, deactivation, or demands immediate KYC verification",
    "Contains shortened or masking URL (often used to obscure malicious links)",
    "Impersonation of Amazon",
    "Threat of account suspension creates false urgency"
  ],
  "safe_actions": [
    "Do not click links claiming your Amazon account or KYC is suspended.",
    "Open the official Amazon app or visit amazon.in directly to check account status.",
    "Amazon does not require third-party APK installations or random SMS links for KYC.",
    "Report the message as spam/phishing."
  ],
  "language": "en",
  "localized_verdict": "Critical Risk: High probability of a dangerous scam or credential theft attempt.",
  "ai_explanation": "This message is a critical phishing attempt. It impersonates Amazon, creates false urgency by claiming account suspension, and attempts to steal your credentials via a masked link.",
  "analysis_mode": "ai_enhanced"
}
```

---

---

## 🧪 Running Automated Tests

Run the full automated test suite (including detector, translations, API schemas, URL analyzer, SSRF defense, voice assistant, and MCP tool mocks):
```powershell
python -m unittest discover -s tests
```
*Expected Result: 65 tests passed (0 failures, 0 errors, full coverage across rule engine, URL analyzer, SSRF blockers, obfuscated IP parsing, DNS rebinding mitigation, and voice assistant).*

---

## 🗣️ Interactive AI Voice Assistant & Link Inspector

The frontend includes an interactive **Scam Shield AI Voice Assistant** that behaves like a friendly conversational companion and automatically detects suspicious links.

> **Note:** This is a simulated Alexa+-style companion and is not officially connected to Amazon's Alexa+ service.

### How to Use Voice & Chat Features

1. Ensure the FastAPI backend is running on `http://127.0.0.1:8000`.
2. Open the frontend in your browser at `http://127.0.0.1:5500`.
3. Scroll to the **"Scam Shield AI Voice Assistant"** card.
4. **Voice Input (Hands-free)**:
   - Click the circular microphone button (`🎙️`) to begin speaking naturally in English, Hindi, or Telugu.
   - The listening status indicator will pulse and recognized speech will appear in the input box.
   - Click the mic button again to stop listening anytime.
5. **Spoken Output**:
   - The assistant speaks its responses aloud using natural browser text-to-speech.
   - Toggle the **🔊 Spoken: On / 🔇 Spoken: Muted** button to mute speech.
   - Click **⏹️ Stop Audio** to cancel speech playback instantly.
6. **Automatic Scam Link Detection**:
   - Whenever you speak or type a message containing a URL (e.g., *"Is this link safe: http://amaz0n-kyc.in?"*), the assistant automatically evaluates the link without needing any extra clicks.
   - An interactive **Link Security Report Card** will appear with:
     - Domain and original URL
     - Live availability status (🟢 Online, 🔴 Unreachable, 🛑 SSRF Blocked)
     - Risk Score and Verdict (Low, Medium, High, Critical)
     - Identified red flags (brand impersonation, shorteners, deceptive subdomains)
     - Actionable protective recommendations
7. **Conversational Companion**:
   - Try saying *"Hi"*, *"I'm bored"*, or asking everyday questions—the assistant responds warmly and empathetically in English, Hindi, or Telugu.

---

## ☁️ Cloud Deployment (MCP Server)

> **Status: NOT YET DEPLOYED.** The MCP server runs locally. Deploy before hackathon submission.

The MCP server reads its bind address and port from environment variables, making it cloud-ready without code changes:

| Variable | Default (local) | Cloud value |
|---|---|---|
| `MCP_HOST` | `127.0.0.1` | `0.0.0.0` |
| `PORT` | `8001` | Assigned by platform |
| `MCP_PATH` | `/mcp` | `/mcp` |
| `GEMINI_API_KEY` | (from `.env`) | Set as secret env var |

### Deploying to Google Cloud Run

```bash
# 1. Build and push container
gcloud run deploy scam-shield-mcp \
  --source . \
  --command "python" \
  --args "app/mcp_server.py" \
  --set-env-vars "MCP_HOST=0.0.0.0,GEMINI_API_KEY=YOUR_KEY" \
  --region us-central1 \
  --allow-unauthenticated

# 2. Your MCP endpoint will be:
# https://scam-shield-mcp-XXXX.run.app/mcp
```

### Deploying to Railway or Render

```bash
# Set these environment variables in the platform dashboard:
MCP_HOST=0.0.0.0
PORT=<platform-assigned>
GEMINI_API_KEY=<your-key>

# Start command:
python app/mcp_server.py
```

After deployment, update the Alexa+ demo `API_BASE` constant in `frontend/index.html` to your public URL.

## 📄 License & Hackathon Notice

Scam Shield is developed for the Amazon Developer Hackathon.

This project is licensed under the MIT License.
See the [LICENSE](LICENSE) file for details.

Scam Shield is an independent project and is not affiliated with,
endorsed by, or officially associated with Amazon.

