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

- **Multilingual Support**: Tailored detection and localized guidance in **English**, **Hindi (हिंदी)**, and **Telugu (తెలుగు)**.
- **Dual-Engine Security Pipeline**:
  - *Deterministic Rule Engine*: Immediate pattern detection for shortened URLs, KYC extortion, OTP solicitation, UPI collect requests, and remote-access APKs.
  - *Google Gemini AI Enhancement*: Deep contextual evaluation of social engineering, tone, novel tactics, and linguistic nuances.
  - *Risk Score Floor Protection*: AI cannot override or lower a high deterministic rule score, ensuring prompt injection cannot bypass security rules.
- **Model Context Protocol (MCP) Server**: Full Streamable HTTP MCP server exposing the `analyze_scam_message` tool for autonomous agents and LLMs.
- **Safe Fallback & Privacy-Preserving Architecture**:
  - Graceful degradation: if Gemini AI is unreachable or unconfigured, the app falls back seamlessly to deterministic rule protection.
  - Messages are evaluated locally on your server without storing personally identifiable information (PII).
- **Accessible, Modern UI**:
  - Amazon-inspired warm amber (`#ff9900`) and cyber-navy aesthetic.
  - Interactive quick-test samples for immediate evaluation.
  - Dynamic character counter and real-time backend health check status pill.

---

## 🛠️ Technology Stack

| Layer | Technologies |
|---|---|
| **Frontend** | Vanilla HTML5, CSS3 (Modern Design System, Responsive Flexbox/Grid), JavaScript (ES6+, Text-only XSS-safe DOM rendering) |
| **Backend API** | FastAPI, Pydantic v2, Uvicorn, Python-dotenv |
| **AI Integration** | Google GenAI SDK (`google-genai`), Gemini 2.5 Flash |
| **Agent / Protocol** | Model Context Protocol (`mcp[cli] 2.3+`), Streamable HTTP Transport |
| **Testing** | Python `unittest`, `httpx`, `fastapi.testclient` |

---

## 🏗️ Architecture

```
[ Incoming Message (SMS / WhatsApp / Email) ]
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
  [ Web Browser UI ]     [ MCP Client / Agent ]
  (Port 5500)             (Port 8001 /mcp)
         │                       │
         ▼                       ▼
┌───────────────────┐   ┌───────────────────────────┐
│   FastAPI Engine  │   │  Scam Shield MCP Server   │
│   (Port 8000)     │   │  (Streamable HTTP)        │
└─────────┬─────────┘   └─────────────┬─────────────┘
          │                           │
          └─────────────┬─────────────┘
                        │
                        ▼
      ┌───────────────────────────────────┐
      │ Deterministic Rule Detector       │
      │ - Keyword & transliteration match │
      │ - URL & remote-access analysis    │
      │ - Risk score baseline (0-100)     │
      └─────────────────┬─────────────────┘
                        │
                        ▼
      ┌───────────────────────────────────┐
      │ Google Gemini AI Analyzer         │
      │ (google-genai / gemini-2.5-flash) │
      │ - Contextual phishing inspection  │
      │ - XML-isolated prompt safety      │
      └─────────────────┬─────────────────┘
                        │
                        ▼
      ┌───────────────────────────────────┐
      │ Scored Verdict & Guidance         │
      │ - Final Score = max(Rule, AI)     │
      │ - Red Flags & Safe Actions        │
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
cd c:\Users\vyasw\OneDrive\Desktop\scam-sheild
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

## 🧪 Running Automated Tests

Run the full automated test suite (including detector, translations, API schemas, and MCP tool mocks):
```powershell
python -m unittest discover -s tests
```
*Expected Result: 21 tests passed (0 failures, 0 errors, no real API calls executed during tests).*

---

## 📄 License & Hackathon Notice

This project is created for the Amazon Developer Hackathon. Open-source licensing will be applied prior to public distribution.
