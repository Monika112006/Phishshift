// PhishShift Light Theme Multi-Channel (Email & SMS) Frontend Logic

let currentChannel = "email";

const INCIDENTS = {
  // Email Incidents
  email_wire: {
    channel: "email",
    subject: "Urgent wire transfer request before end of day",
    body: "Hi, I am currently in a closed-door meeting and unable to take phone calls. Please process an urgent vendor invoice payment of $34,500. Wire instructions link: hxxp://bit[.]ly/3xVendorPay",
    sender: "free_webmail",
    url: "hxxp://bit[.]ly/3xVendorPay"
  },
  email_reset: {
    channel: "email",
    subject: "Internal IT: Password Reset Request Confirmed",
    body: "Hello, your request to reset your enterprise domain password has been received. If you initiated this request, use your single-use recovery code 491022. If not, contact Helpdesk immediately at ext. 4400. SSO Portal: hxxps://sso.internal.corp[.]local/security/audit",
    sender: "internal_corporate",
    url: "hxxps://sso.internal.corp[.]local/security/audit"
  },
  email_novel: {
    channel: "email",
    subject: "System Diagnostic: Periodic token synchronization challenge",
    body: "In accordance with updated telemetry baseline policies, your authenticator seed requires re-alignment. Proceed with the automated handshake: hxxp://telemetry-handshake-broker[.]xyz/challenge",
    sender: "suspicious_random",
    url: "hxxp://telemetry-handshake-broker[.]xyz/challenge"
  },
  email_abstain: {
    channel: "email",
    subject: "Administrative notice regarding vendor transition",
    body: "Please be advised that contract accounts will be updated next quarter. Further details will follow in due course: hxxps://intranet.corp.internal[.]net/docs",
    sender: "external_partner",
    url: "hxxps://intranet.corp.internal[.]net/docs"
  },

  // SMS Incidents
  sms_package: {
    channel: "sms",
    subject: "SMS Notification",
    body: "USPS: Package US492109X could not be delivered due to incomplete address. Please pay $2.45 customs redelivery fee within 12h: hxxp://tinyurl[.]com/usps-track-994",
    sender: "suspicious_random",
    url: "hxxp://tinyurl[.]com/usps-track-994"
  },
  sms_duo: {
    channel: "sms",
    subject: "MFA Verification",
    body: "Your Duo Security verification code is 849201. Do not share this code with anyone. It expires in 5 minutes.",
    sender: "internal_corporate",
    url: ""
  },
  sms_bank: {
    channel: "sms",
    subject: "Fraud Alert",
    body: "Chase Fraud Alert: Suspicious debit charge of $1,420.00 detected on card ending 4019. If unauthorized, verify identity immediately: hxxp://chase-security-auth[.]top/verify",
    sender: "spoofed_lookalike",
    url: "hxxp://chase-security-auth[.]top/verify"
  }
};

function switchChannel(channel) {
  currentChannel = channel;
  const btnEmail = document.getElementById("tab-email");
  const btnSms = document.getElementById("tab-sms");
  const modeLabel = document.getElementById("active-mode-label");
  const groupSubject = document.getElementById("group-subject");
  const labelBody = document.getElementById("label-body");
  const emailPresets = document.getElementById("email-presets");
  const smsPresets = document.getElementById("sms-presets");

  if (channel === "email") {
    btnEmail.classList.add("active");
    btnSms.classList.remove("active");
    modeLabel.textContent = "EMAIL MODE";
    groupSubject.style.display = "block";
    labelBody.textContent = "Email Body Content";
    emailPresets.style.display = "flex";
    smsPresets.style.display = "none";
  } else {
    btnSms.classList.add("active");
    btnEmail.classList.remove("active");
    modeLabel.textContent = "SMS MODE";
    groupSubject.style.display = "none";
    labelBody.textContent = "SMS Message Content (Mobile Channel)";
    emailPresets.style.display = "none";
    smsPresets.style.display = "flex";
  }
}

function loadSample(key) {
  const inc = INCIDENTS[key];
  if (!inc) return;

  if (inc.channel !== currentChannel) {
    switchChannel(inc.channel);
  }

  document.getElementById("input-subject").value = inc.subject || "";
  document.getElementById("input-body").value = inc.body || "";
  document.getElementById("input-sender").value = inc.sender || "internal_corporate";
  document.getElementById("input-url").value = inc.url || "";
}

async function handleTriageSubmit(e) {
  e.preventDefault();
  const btn = document.getElementById("btn-submit");
  const badge = document.getElementById("telemetry-badge");

  btn.textContent = "Classifying Risk...";
  btn.disabled = true;
  badge.textContent = "ANALYZING";
  badge.style.color = "#2563eb";

  const subject = currentChannel === "email" ? document.getElementById("input-subject").value.trim() : "SMS Alert";
  const body = document.getElementById("input-body").value.trim();
  const senderType = document.getElementById("input-sender").value;
  const inertUrl = document.getElementById("input-url").value.trim();

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        subject: subject,
        body: body,
        sender_domain_type: senderType,
        channel: currentChannel,
        inert_url: inertUrl
      })
    });
    const data = await res.json();
    renderTriageResults(data);
    badge.textContent = "TRIAGED";
    badge.style.color = "#059669";
  } catch (err) {
    alert("Connection Error: " + err.message);
    badge.textContent = "ERROR";
    badge.style.color = "#e11d48";
  } finally {
    btn.textContent = "Classify & Scan Message Risk";
    btn.disabled = false;
  }
}

function renderTriageResults(data) {
  document.getElementById("results-placeholder").style.display = "none";
  const container = document.getElementById("results-container");
  container.style.display = "block";

  // Channel Classification Pill
  const channelPill = document.getElementById("channel-result-pill");
  if (currentChannel === "sms") {
    channelPill.innerHTML = "<span>💬</span> CLASSIFIED AS: SMS COMMUNICATION";
  } else {
    channelPill.innerHTML = "<span>✉️</span> CLASSIFIED AS: EMAIL MESSAGE";
  }

  // Verdict Card
  const vCard = document.getElementById("verdict-card");
  vCard.className = "triage-verdict-card " + data.verdict_badge;

  let title = data.verdict;
  let sub = "Standard baseline telemetry";
  if (data.verdict_badge === "danger") {
    title = currentChannel === "sms" ? "SUSPICIOUS SMISHING DETECTED" : "SUSPICIOUS PHISHING DETECTED";
    sub = "High-risk indicators identified";
  } else if (data.verdict_badge === "safe") {
    title = currentChannel === "sms" ? "VERIFIED LEGITIMATE SMS" : "VERIFIED LEGITIMATE EMAIL";
    sub = "Trusted corporate communications baseline";
  } else if (data.verdict_badge === "warning") {
    title = "ABSTAIN / ESCALATE FOR HUMAN REVIEW";
    sub = "Prediction uncertainty zone or model variance";
  }

  document.getElementById("verdict-title").textContent = title;
  document.getElementById("verdict-subtitle").textContent = sub;

  const pct = Math.round(data.composite_risk_score * 100);
  document.getElementById("score-val").textContent = `${pct}%`;

  // Abstain Box (FR-04)
  const abstainBox = document.getElementById("abstain-box");
  if (data.is_abstain) {
    abstainBox.style.display = "block";
    document.getElementById("abstain-text").textContent = data.abstain_reason;
  } else {
    abstainBox.style.display = "none";
  }

  // Indicators / Explanations
  const evidenceContainer = document.getElementById("evidence-items");
  evidenceContainer.innerHTML = "";

  const items = [];
  (data.risk_cues || []).forEach(c => items.push({ type: "risk", tag: c.category, text: c.cue }));
  (data.safe_cues || []).forEach(c => items.push({ type: "safe", tag: c.category, text: c.cue }));

  if (items.length === 0) {
    evidenceContainer.innerHTML = `
      <div class="evidence-item">
        <span class="evidence-tag safe">BENIGN</span>
        <span class="evidence-text">Standard enterprise communication pattern with no critical anomalies.</span>
      </div>`;
  } else {
    items.slice(0, 6).forEach(it => {
      const row = document.createElement("div");
      row.className = "evidence-item";
      row.innerHTML = `
        <span class="evidence-tag ${it.type}">${it.tag}</span>
        <span class="evidence-text">${it.text}</span>`;
      evidenceContainer.appendChild(row);
    });
  }

  // Multi-Engine Consensus (FR-02)
  const mb = data.model_breakdown;
  document.getElementById("score-rules").textContent = mb.rule_based.risk_score.toFixed(2);
  document.getElementById("score-tfidf").textContent = mb.tfidf_linear.risk_score.toFixed(2);
  document.getElementById("score-rf").textContent = mb.ensemble_forest.risk_score.toFixed(2);

  // Smooth scroll
  container.scrollIntoView({ behavior: "smooth", block: "nearest" });
}
