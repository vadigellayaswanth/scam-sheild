/**
 * Scam Shield - Frontend Logic
 * Connects to local FastAPI backend (POST /analyze, GET /health)
 * Features:
 * - Real API queries on form submit & quick-test chips
 * - Dynamic character counting
 * - Accurate status indication (AI Enhanced vs Rule-Based Shield)
 * - Safe rendering without innerHTML injection of untrusted user messages
 * - Session-based local scan history (lightweight, client-only)
 */

const API_BASE_URL = "http://127.0.0.1:8000";

// Predefined realistic quick-test scenarios
const QUICK_EXAMPLES = {
  kyc: {
    text: "Amazon: Your account has been suspended due to pending KYC verification. Update your PAN card and Aadhaar immediately at http://amz-kyc-verify.in to restore access.",
    lang: "en",
  },
  otp: {
    text: "Amazon Customer Support: We detected an unauthorized purchase of Rs. 42,999 on your card. To cancel this transaction immediately, please share the 6-digit OTP sent to your phone.",
    lang: "en",
  },
  delivery: {
    text: "Amazon Delivery: Package #94827 could not be delivered due to incomplete address. Pay Rs. 25 re-delivery fee at http://bit.ly/amz-pkg-redeliver or your order will be cancelled.",
    lang: "en",
  },
  prize: {
    text: "Congratulations! You won a FREE iPhone 15 in the Amazon Annual Festive Lucky Draw. Claim your gift now by clicking: http://amazon-festive-rewards.xyz",
    lang: "en",
  },
  legit: {
    text: "Your Amazon package with tracking #7264819283 has been delivered to your front door. Track your order anytime in the official Amazon app.",
    lang: "en",
  },
};

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("scam-form");
  const messageInput = document.getElementById("message-input");
  const charCounter = document.getElementById("char-counter");
  const languageSelect = document.getElementById("language-select");
  const checkBtn = document.getElementById("check-btn");
  const resetBtn = document.getElementById("reset-btn");

  const systemStatusPill = document.getElementById("system-status-pill");
  const systemStatusText = document.getElementById("system-status-text");

  const loadingState = document.getElementById("loading-state");
  const errorBox = document.getElementById("error-box");
  const errorTitle = document.getElementById("error-title");
  const errorMessage = document.getElementById("error-message");

  const resultsSection = document.getElementById("results-section");
  const scoreNumber = document.getElementById("score-number");
  const scoreBarFill = document.getElementById("score-bar-fill");
  const verdictBadge = document.getElementById("verdict-badge");
  const verdictIcon = document.getElementById("verdict-icon");
  const verdictText = document.getElementById("verdict-text");
  const analysisModeBadge = document.getElementById("analysis-mode-badge");
  const modeIcon = document.getElementById("mode-icon");
  const modeText = document.getElementById("mode-text");

  const localizedVerdict = document.getElementById("localized-verdict");
  const categoryText = document.getElementById("category-text");
  const aiExplanationBlock = document.getElementById("ai-explanation-block");
  const aiExplanationText = document.getElementById("ai-explanation-text");
  const highRiskBanner = document.getElementById("high-risk-banner");

  const redFlagsCount = document.getElementById("red-flags-count");
  const redFlagsList = document.getElementById("red-flags-list");
  const safeActionsCount = document.getElementById("safe-actions-count");
  const safeActionsList = document.getElementById("safe-actions-list");
  const safetyAdviceBlock = document.getElementById("safety-advice-block");
  const localizedSafetyAdvice = document.getElementById("localized-safety-advice");

  const historySection = document.getElementById("history-section");
  const historyList = document.getElementById("history-list");
  const clearHistoryBtn = document.getElementById("clear-history-btn");

  // Keep in-memory session history
  let sessionHistory = [];

  // Initialize System Health Check
  checkBackendHealth();

  // Character counter listener
  messageInput.addEventListener("input", updateCharCounter);

  function updateCharCounter() {
    const len = messageInput.value.length;
    charCounter.textContent = `${len} ${len === 1 ? "character" : "characters"}`;
  }

  // Handle Form Submit
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    await handleAnalyze();
  });

  // Handle Reset / Clear
  resetBtn.addEventListener("click", () => {
    messageInput.value = "";
    updateCharCounter();
    messageInput.focus();
    hideAllResults();
    hideError();
  });

  // Quick-Test Chips listener
  const chipButtons = document.querySelectorAll(".chip-btn");
  chipButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const exampleKey = btn.getAttribute("data-example");
      const sample = QUICK_EXAMPLES[exampleKey];
      if (sample) {
        messageInput.value = sample.text;
        updateCharCounter();
        if (sample.lang) {
          languageSelect.value = sample.lang;
        }
        handleAnalyze();
      }
    });
  });

  // Clear Session History
  if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener("click", () => {
      sessionHistory = [];
      renderSessionHistory();
    });
  }

  async function checkBackendHealth() {
    try {
      const response = await fetch(`${API_BASE_URL}/health`);
      if (response.ok) {
        systemStatusPill.className = "status-pill status-ai";
        systemStatusText.textContent = "Online & Protected";
      } else {
        systemStatusPill.className = "status-pill status-rule";
        systemStatusText.textContent = "Backend Connecting...";
      }
    } catch (_) {
      systemStatusPill.className = "status-pill status-rule";
      systemStatusText.textContent = "Backend Offline";
    }
  }

  async function handleAnalyze() {
    const rawMessage = messageInput.value;
    const trimmedMessage = rawMessage.trim();
    const language = languageSelect.value;

    hideError();
    hideAllResults();

    if (!trimmedMessage) {
      showError(
        "Please enter a message",
        "Paste the text of the suspicious SMS, WhatsApp alert, or email you would like to evaluate."
      );
      messageInput.focus();
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: trimmedMessage,
          language: language,
        }),
      });

      if (!response.ok) {
        let errorDetail = `Server responded with HTTP ${response.status}`;
        try {
          const errData = await response.json();
          if (errData && errData.detail) {
            if (typeof errData.detail === "string") {
              errorDetail = errData.detail;
            } else if (Array.isArray(errData.detail) && errData.detail[0]?.msg) {
              errorDetail = errData.detail[0].msg;
            }
          }
        } catch (_) {
          // Keep default fallback
        }
        showError("Analysis Request Failed", errorDetail);
        return;
      }

      const data = await response.json();
      renderResults(data, trimmedMessage);

      // Record to session history
      addToSessionHistory({
        text: trimmedMessage,
        score: data.risk_score,
        verdict: data.verdict,
        category: data.category,
        time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      });

    } catch (networkError) {
      showError(
        "Backend Service Unavailable",
        "Could not connect to Scam Shield server at " +
          API_BASE_URL +
          ". Please verify the FastAPI backend is running (e.g. `python -m uvicorn app.main:app --reload`)."
      );
    } finally {
      setLoading(false);
    }
  }

  function renderResults(data, originalMessage) {
    const score = Number.isInteger(data.risk_score) ? data.risk_score : 0;
    const verdict = (data.verdict || "low").toLowerCase();

    // 1. Score display & progress bar
    scoreNumber.textContent = score;
    scoreBarFill.style.width = `${Math.min(100, Math.max(0, score))}%`;

    // Visual Palette by verdict
    const colorMap = {
      low: "#16a34a",
      medium: "#d97706",
      high: "#dc2626",
      critical: "#991b1b",
    };
    const iconMap = {
      low: "✅",
      medium: "⚠️",
      high: "🚨",
      critical: "🛑",
    };

    scoreBarFill.style.backgroundColor = colorMap[verdict] || "#2563eb";

    // 2. Verdict Pill
    verdictBadge.className = `verdict-pill verdict-${verdict}`;
    verdictIcon.textContent = iconMap[verdict] || "🛡️";
    verdictText.textContent = `${verdict.toUpperCase()} RISK`;

    // 3. Category & Localized Verdict
    categoryText.textContent = data.category || "General Inquiry";
    if (data.localized_verdict) {
      localizedVerdict.textContent = data.localized_verdict;
      localizedVerdict.classList.remove("hidden");
    } else {
      localizedVerdict.textContent = "";
      localizedVerdict.classList.add("hidden");
    }

    // 4. Analysis Mode Badge
    if (data.analysis_mode === "ai_enhanced") {
      modeIcon.textContent = "⚡";
      modeText.textContent = "AI Enhanced (Gemini)";
      analysisModeBadge.className = "mode-badge mode-badge-ai";
      systemStatusPill.className = "status-pill status-ai";
      systemStatusText.textContent = "AI Mode Active";
    } else {
      modeIcon.textContent = "🛡️";
      modeText.textContent = "Rule-Based Shield";
      analysisModeBadge.className = "mode-badge mode-badge-rule";
      systemStatusPill.className = "status-pill status-rule";
      systemStatusText.textContent = "Rule-Based Engine";
    }

    // 5. AI Explanation Handling
    // If AI explanation is present and we're in AI mode, display it proudly.
    // If we're in rule-based mode, check if there is a safe diagnostic explanation to show helpfully.
    if (data.ai_explanation && data.analysis_mode === "ai_enhanced") {
      aiExplanationText.textContent = data.ai_explanation;
      aiExplanationBlock.classList.remove("hidden");
    } else if (data.ai_explanation && data.analysis_mode === "rule_based" && !data.ai_explanation.includes("configured")) {
      aiExplanationText.textContent = data.ai_explanation;
      aiExplanationBlock.classList.remove("hidden");
    } else {
      aiExplanationText.textContent = "";
      aiExplanationBlock.classList.add("hidden");
    }

    // 6. High Risk Banner
    if (verdict === "high" || verdict === "critical") {
      highRiskBanner.classList.remove("hidden");
    } else {
      highRiskBanner.classList.add("hidden");
    }

    // 7. Red Flags List (Text-only rendering to prevent XSS)
    redFlagsList.innerHTML = "";
    const redFlags = Array.isArray(data.red_flags) ? data.red_flags : [];
    redFlagsCount.textContent = redFlags.length;

    if (redFlags.length === 0) {
      const li = document.createElement("li");
      li.textContent = "No prominent scam patterns or malicious triggers detected in this text.";
      redFlagsList.appendChild(li);
    } else {
      redFlags.forEach((flag) => {
        const li = document.createElement("li");
        li.textContent = flag;
        redFlagsList.appendChild(li);
      });
    }

    // 8. Safe Actions List (Text-only rendering)
    safeActionsList.innerHTML = "";
    const safeActions = Array.isArray(data.safe_actions) ? data.safe_actions : [];
    safeActionsCount.textContent = safeActions.length;

    if (safeActions.length === 0) {
      const li = document.createElement("li");
      li.textContent = "Verify all orders and account alerts directly via the official Amazon app.";
      safeActionsList.appendChild(li);
    } else {
      safeActions.forEach((action) => {
        const li = document.createElement("li");
        li.textContent = action;
        safeActionsList.appendChild(li);
      });
    }

    // 9. Localized General Safety Advice
    if (data.localized_safety_advice) {
      localizedSafetyAdvice.textContent = data.localized_safety_advice;
      safetyAdviceBlock.classList.remove("hidden");
    } else {
      localizedSafetyAdvice.textContent = "";
      safetyAdviceBlock.classList.add("hidden");
    }

    resultsSection.classList.remove("hidden");
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function addToSessionHistory(item) {
    sessionHistory.unshift(item);
    if (sessionHistory.length > 5) {
      sessionHistory.pop();
    }
    renderSessionHistory();
  }

  function renderSessionHistory() {
    if (!historySection || !historyList) return;

    if (sessionHistory.length === 0) {
      historySection.classList.add("hidden");
      historyList.innerHTML = "";
      return;
    }

    historyList.innerHTML = "";
    sessionHistory.forEach((scan) => {
      const itemEl = document.createElement("div");
      itemEl.className = "history-item";
      itemEl.setAttribute("role", "button");
      itemEl.setAttribute("tabindex", "0");
      itemEl.title = "Click to inspect this message again";

      const contentEl = document.createElement("div");
      contentEl.className = "history-item-content";

      const textEl = document.createElement("span");
      textEl.className = "history-item-text";
      textEl.textContent = scan.text;

      contentEl.appendChild(textEl);

      const pillEl = document.createElement("span");
      pillEl.className = `history-score-pill verdict-${scan.verdict}`;
      pillEl.textContent = `${scan.score}/100`;

      itemEl.appendChild(contentEl);
      itemEl.appendChild(pillEl);

      itemEl.addEventListener("click", () => {
        messageInput.value = scan.text;
        updateCharCounter();
        handleAnalyze();
      });

      itemEl.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          messageInput.value = scan.text;
          updateCharCounter();
          handleAnalyze();
        }
      });

      historyList.appendChild(itemEl);
    });

    historySection.classList.remove("hidden");
  }

  function setLoading(isLoading) {
    if (isLoading) {
      loadingState.classList.remove("hidden");
      checkBtn.disabled = true;
      resetBtn.disabled = true;
    } else {
      loadingState.classList.add("hidden");
      checkBtn.disabled = false;
      resetBtn.disabled = false;
    }
  }

  function showError(title, message) {
    errorTitle.textContent = title;
    errorMessage.textContent = message;
    errorBox.classList.remove("hidden");
    errorBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function hideError() {
    errorBox.classList.add("hidden");
  }

  function hideAllResults() {
    resultsSection.classList.add("hidden");
  }
});
