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

  /* ══════════════════════════════════════════════════════════
     Interactive Voice Assistant & Automatic Link Inspection Logic
     ══════════════════════════════════════════════════════════ */
  let assistantHistory = [];
  let isListening = false;
  let isMuted = false;
  let recognition = null;

  const voiceRing = document.getElementById("voice-ring");
  const audioWaveBars = document.getElementById("audio-wave-bars");
  const voiceMuteBtn = document.getElementById("voice-mute-btn");
  const voiceMuteIcon = document.getElementById("voice-mute-icon");
  const voiceMuteLabel = document.getElementById("voice-mute-label");
  const voiceStopSpeechBtn = document.getElementById("voice-stop-speech-btn");
  const voiceStatusBanner = document.getElementById("voice-status-banner");
  const voiceStatusText = document.getElementById("voice-status-text");
  const thread = document.getElementById("assistant-conversation-thread");
  const assistantForm = document.getElementById("assistant-input-form");
  const voiceMicBtn = document.getElementById("voice-mic-btn");
  const assistantTextInput = document.getElementById("assistant-text-input");
  const assistantSendBtn = document.getElementById("assistant-send-btn");
  const clearChatBtn = document.getElementById("clear-chat-btn");
  const promptChips = document.querySelectorAll(".assistant-prompt-chip");

  // Initialize Speech Recognition
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (SpeechRecognition) {
    recognition = new SpeechRecognition();
    recognition.continuous = false;
    recognition.interimResults = true;

    recognition.onstart = () => {
      isListening = true;
      voiceMicBtn.classList.add("active");
      setVoiceRingState("listening");
      showVoiceStatus("Listening... Speak naturally now");
    };

    recognition.onresult = (event) => {
      let interimTranscript = "";
      let finalTranscript = "";
      for (let i = event.resultIndex; i < event.results.length; ++i) {
        if (event.results[i].isFinal) {
          finalTranscript += event.results[i][0].transcript;
        } else {
          interimTranscript += event.results[i][0].transcript;
        }
      }
      const captured = finalTranscript || interimTranscript;
      if (captured) {
        assistantTextInput.value = captured;
      }
    };

    recognition.onerror = (event) => {
      isListening = false;
      voiceMicBtn.classList.remove("active");
      setVoiceRingState("idle");
      if (event.error === "not-allowed" || event.error === "permission-denied") {
        showVoiceStatus("Microphone access was blocked. You can continue typing below.", 5000);
      } else if (event.error !== "no-speech") {
        showVoiceStatus(`Voice input notice: ${event.error}. You can type your message.`, 4000);
      } else {
        hideVoiceStatus();
      }
    };

    recognition.onend = () => {
      isListening = false;
      voiceMicBtn.classList.remove("active");
      setVoiceRingState("idle");
      hideVoiceStatus();
      const captured = assistantTextInput.value.trim();
      if (captured) {
        handleAssistantSend(captured);
      }
    };
  }

  // Toggle Microphone
  if (voiceMicBtn) {
    voiceMicBtn.addEventListener("click", () => {
      stopSpeechPlayback();

      if (!recognition) {
        showVoiceStatus("Speech recognition is not supported in this browser. Please type your message.", 4000);
        assistantTextInput.focus();
        return;
      }

      if (isListening) {
        try { recognition.stop(); } catch (_) {}
      } else {
        assistantTextInput.value = "";
        const lang = languageSelect ? languageSelect.value : "en";
        recognition.lang = lang === "hi" ? "hi-IN" : lang === "te" ? "te-IN" : "en-IN";
        try {
          recognition.start();
        } catch (e) {
          console.warn("Could not start recognition:", e);
        }
      }
    });
  }

  // Toggle Mute / Spoken Responses
  if (voiceMuteBtn) {
    voiceMuteBtn.addEventListener("click", () => {
      isMuted = !isMuted;
      if (isMuted) {
        stopSpeechPlayback();
        voiceMuteIcon.textContent = "🔇";
        voiceMuteLabel.textContent = "Spoken: Muted";
        voiceMuteBtn.style.opacity = "0.75";
      } else {
        voiceMuteIcon.textContent = "🔊";
        voiceMuteLabel.textContent = "Spoken: On";
        voiceMuteBtn.style.opacity = "1";
      }
    });
  }

  // Stop Speech Playback Button
  if (voiceStopSpeechBtn) {
    voiceStopSpeechBtn.addEventListener("click", () => {
      stopSpeechPlayback();
    });
  }

  // Voice Ring click triggers mic or stops speech
  if (voiceRing) {
    voiceRing.addEventListener("click", () => {
      if (window.speechSynthesis && window.speechSynthesis.speaking) {
        stopSpeechPlayback();
      } else if (voiceMicBtn) {
        voiceMicBtn.click();
      }
    });
  }

  // Preset quick prompt chips
  promptChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      const promptText = chip.getAttribute("data-prompt");
      if (promptText) {
        assistantTextInput.value = promptText;
        handleAssistantSend(promptText);
      }
    });
  });

  // Assistant Form Submit
  if (assistantForm) {
    assistantForm.addEventListener("submit", (e) => {
      e.preventDefault();
      handleAssistantSend();
    });
  }

  // Clear Chat Button
  if (clearChatBtn) {
    clearChatBtn.addEventListener("click", () => {
      stopSpeechPlayback();
      assistantHistory = [];
      thread.innerHTML = `
        <div class="msg-bubble-row assistant-row">
          <div class="bubble-avatar assistant-avatar" aria-hidden="true">🛡️</div>
          <div class="msg-bubble assistant-bubble">
            <p>Chat cleared! 😊 Feel free to speak or type a new message or link.</p>
          </div>
        </div>
      `;
    });
  }

  function setVoiceRingState(state) {
    if (!voiceRing) return;
    voiceRing.className = `voice-ring ${state}`;
    if (audioWaveBars) {
      if (state === "listening" || state === "speaking") {
        audioWaveBars.classList.remove("hidden");
      } else {
        audioWaveBars.classList.add("hidden");
      }
    }
  }

  function showVoiceStatus(text, autoHideMs = null) {
    if (!voiceStatusBanner || !voiceStatusText) return;
    voiceStatusText.textContent = text;
    voiceStatusBanner.classList.remove("hidden");
    if (autoHideMs) {
      setTimeout(() => hideVoiceStatus(), autoHideMs);
    }
  }

  function hideVoiceStatus() {
    if (voiceStatusBanner) {
      voiceStatusBanner.classList.add("hidden");
    }
  }

  function speakText(text, lang) {
    if (isMuted || !window.speechSynthesis || !text) return;
    stopSpeechPlayback();

    const cleanText = text.replace(/[*_#`~\[\]<>]/g, "").trim();
    if (!cleanText) return;

    const utterance = new SpeechSynthesisUtterance(cleanText);
    const targetLang = lang === "hi" ? "hi-IN" : lang === "te" ? "te-IN" : "en-IN";
    utterance.lang = targetLang;
    utterance.rate = 1.0;

    // Pick suitable voice matching target language
    const voices = window.speechSynthesis.getVoices();
    if (voices && voices.length > 0) {
      const match = voices.find((v) =>
        v.lang.toLowerCase().startsWith(lang === "hi" ? "hi" : lang === "te" ? "te" : "en")
      );
      if (match) utterance.voice = match;
    }

    utterance.onstart = () => {
      setVoiceRingState("speaking");
      if (voiceStopSpeechBtn) voiceStopSpeechBtn.classList.remove("hidden");
    };

    utterance.onend = () => {
      setVoiceRingState("idle");
      if (voiceStopSpeechBtn) voiceStopSpeechBtn.classList.add("hidden");
    };

    utterance.onerror = () => {
      setVoiceRingState("idle");
      if (voiceStopSpeechBtn) voiceStopSpeechBtn.classList.add("hidden");
    };

    window.speechSynthesis.speak(utterance);
  }

  function stopSpeechPlayback() {
    if (window.speechSynthesis) {
      window.speechSynthesis.cancel();
    }
    setVoiceRingState("idle");
    if (voiceStopSpeechBtn) voiceStopSpeechBtn.classList.add("hidden");
  }

  function appendBubble(role, html) {
    const row = document.createElement("div");
    row.className = `msg-bubble-row ${role === "user" ? "user-row" : "assistant-row"}`;

    const avatar = document.createElement("div");
    avatar.className = `bubble-avatar ${role === "user" ? "user-avatar" : "assistant-avatar"}`;
    avatar.textContent = role === "user" ? "You" : "🛡️";

    const bubble = document.createElement("div");
    bubble.className = `msg-bubble ${role === "user" ? "user-bubble" : "assistant-bubble"}`;
    bubble.innerHTML = html;

    row.appendChild(avatar);
    row.appendChild(bubble);
    thread.appendChild(row);
    thread.scrollTop = thread.scrollHeight;
    return bubble;
  }

  function renderAssistantBubbleContent(bubbleEl, data) {
    let html = formatMarkdownToSafeHtml(data.reply);

    // If URLs were automatically detected, render structured link report cards
    if (data.urls_detected && data.urls_detected.length > 0) {
      data.urls_detected.forEach((urlData) => {
        const vc = ["critical", "high", "medium", "low"].includes(urlData.verdict)
          ? urlData.verdict
          : "medium";

        const avail = urlData.availability || "unknown";
        const availLabel = {
          online: "🟢 Online",
          unreachable: "🔴 Unreachable",
          blocked_ssrf: "🛑 Blocked (SSRF Security)",
          server_error: "⚠️ Server Error",
          invalid_scheme: "⚠️ Invalid Scheme",
          unknown: "⚪ Status Unknown",
        }[avail] || avail.toUpperCase();

        const flagsHtml = (urlData.red_flags || [])
          .map((f) => `<li>${escHtml(f)}</li>`)
          .join("");

        const actionsHtml = (urlData.safe_actions || [])
          .map((a) => `<li>${escHtml(a)}</li>`)
          .join("");

        const verdictLabel = urlData.verdict_label || urlData.verdict.toUpperCase();
        const conf = urlData.confidence ? ` &bull; ${urlData.confidence.toUpperCase()} CONFIDENCE` : "";
        const regDom = urlData.registered_domain && urlData.registered_domain !== urlData.domain
          ? `<span style="font-size:0.75rem;color:var(--text-muted);margin-left:4px;">(Apex: ${escHtml(urlData.registered_domain)})</span>`
          : "";

        const tiBadge = urlData.threat_intelligence && urlData.threat_intelligence.checked
          ? `<span style="font-size:0.72rem;background:#dbeafe;color:#1e40af;padding:2px 7px;border-radius:9999px;font-weight:600;">🛡️ Safe Browsing: ${escHtml(urlData.threat_intelligence.status.toUpperCase())}</span>`
          : "";

        html += `
          <div class="link-card-inline">
            <div class="link-card-header">
              <span class="link-domain-badge">🔗 ${escHtml(urlData.domain || urlData.url)} ${regDom}</span>
              <div class="link-pills-row">
                ${tiBadge}
                <span class="link-avail-pill ${avail}">${availLabel}</span>
                <span class="link-score-badge ${vc}">Risk ${urlData.risk_score}/100 — ${escHtml(verdictLabel)}${conf}</span>
              </div>
            </div>
            <div class="link-field-row"><strong>Category:</strong> ${escHtml(urlData.category)}</div>
            ${urlData.redirect_destination && urlData.redirect_destination !== urlData.url ? `<div class="link-field-row"><strong>Redirect Destination:</strong> <code>${escHtml(urlData.redirect_destination)}</code></div>` : ""}
            ${flagsHtml ? `<strong style="font-size:0.78rem;color:#b91c1c;">Detected Evidence / Red Flags:</strong><ul class="link-flags-list">${flagsHtml}</ul>` : ""}
            ${actionsHtml ? `<strong style="font-size:0.78rem;color:#15803d;">Recommended Actions:</strong><ul class="link-actions-list">${actionsHtml}</ul>` : ""}
            <div class="mcp-tool-pill">🔌 MCP Security Tool: <code>analyze_scam_url</code> (SSRF Guarded)</div>
          </div>
        `;
      });
    }

    // Add Replay Voice Button
    if (data.speech_text) {
      const replayId = `replay-btn-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
      html += `
        <div>
          <button type="button" class="play-bubble-btn" id="${replayId}">
            <span>🔊</span> <span>Listen Aloud</span>
          </button>
        </div>
      `;
      bubbleEl.innerHTML = html;

      const replayBtn = document.getElementById(replayId);
      if (replayBtn) {
        replayBtn.addEventListener("click", () => {
          speakText(data.speech_text, data.language);
        });
      }
    } else {
      bubbleEl.innerHTML = html;
    }

    thread.scrollTop = thread.scrollHeight;
  }

  function formatMarkdownToSafeHtml(md) {
    if (!md) return "";
    let safe = escHtml(md);
    // Convert bold **text** to <strong>
    safe = safe.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
    // Convert *text* to <em>
    safe = safe.replace(/\*(.*?)\*/g, "<em>$1</em>");
    // Convert `code` to <code>
    safe = safe.replace(/`([^`]+)`/g, "<code>$1</code>");
    // Convert newlines to paragraphs / breaks
    const paragraphs = safe.split(/\n\n+/);
    return paragraphs.map((p) => `<p>${p.replace(/\n/g, "<br>")}</p>`).join("");
  }

  async function handleAssistantSend(providedText = null) {
    const raw = providedText !== null ? providedText : assistantTextInput.value;
    const text = (raw || "").trim();
    if (!text) {
      assistantTextInput.focus();
      return;
    }

    assistantTextInput.value = "";
    stopSpeechPlayback();

    // 1. Append User Bubble
    appendBubble("user", escHtml(text));

    // 2. Append Thinking Bubble
    const thinkingBubble = appendBubble(
      "assistant",
      '<span style="font-style:italic;color:var(--text-muted);display:flex;align-items:center;gap:6px;"><span class="status-pulse-dot" style="animation-duration:0.8s;"></span> Thinking & checking links…</span>'
    );
    setVoiceRingState("thinking");

    assistantSendBtn.disabled = true;
    const currentLang = languageSelect ? languageSelect.value : "en";

    try {
      const resp = await fetch(`${API_BASE_URL}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: text,
          language: currentLang,
          history: assistantHistory.slice(-4),
          auto_analyze_links: true,
        }),
      });

      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({}));
        throw new Error(errData.detail || `Server error (HTTP ${resp.status})`);
      }

      const data = await resp.json();

      // Render response
      renderAssistantBubbleContent(thinkingBubble, data);

      // Record in session conversation memory
      assistantHistory.push({ role: "user", content: text });
      assistantHistory.push({ role: "assistant", content: data.reply });

      // Speak aloud
      if (data.speech_text) {
        speakText(data.speech_text, currentLang);
      } else {
        setVoiceRingState("idle");
      }
    } catch (err) {
      thinkingBubble.innerHTML = `<span style="color:#b91c1c;">⚠️ Voice Assistant Error: ${escHtml(err.message)}</span>`;
      setVoiceRingState("idle");
    } finally {
      assistantSendBtn.disabled = false;
    }
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
});
