const STORAGE_KEY = "novacart-cyberagent-config";
const TARGET_IP = "10.0.0.12";

const apiBaseInput = document.getElementById("apiBase");
const collectorTokenInput = document.getElementById("collectorToken");
const sourceLabelInput = document.getElementById("sourceLabel");
const collectorStatus = document.getElementById("collectorStatus");
const activityLog = document.getElementById("activityLog");

function isoNow() {
  return new Date().toISOString();
}

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function accessEvent(srcIp, path, method = "GET", statusCode = 200, userAgent = "novacart-browser", bytes = 640) {
  const timestamp = isoNow();
  return {
    event_type: "access",
    timestamp,
    src_ip: srcIp,
    path,
    method,
    status_code: statusCode,
    bytes_sent: bytes,
    user_agent: userAgent,
    message: `${timestamp} ACCESS src=${srcIp} method=${method} path=${path} status=${statusCode} bytes=${bytes} user_agent=${userAgent}`,
  };
}

function authEvent(srcIp, username, result, port = 22) {
  const timestamp = isoNow();
  return {
    event_type: "auth",
    timestamp,
    src_ip: srcIp,
    username,
    result,
    port,
    message: `${timestamp} AUTH service=sshd src=${srcIp} user=${username} result=${result} port=${port}`,
  };
}

function networkEvent(srcIp, dstIp, port, packets, bytesSent, flags = "ACK") {
  const timestamp = isoNow();
  return {
    event_type: "network",
    timestamp,
    src_ip: srcIp,
    dst_ip: dstIp,
    port,
    protocol: "TCP",
    packets,
    bytes_sent: bytesSent,
    flags,
    message: `${timestamp} NETFLOW src=${srcIp} dst=${dstIp}:${port} proto=TCP packets=${packets} bytes=${bytesSent} flags=${flags}`,
  };
}

function getConfig() {
  return {
    apiBase: apiBaseInput.value.trim(),
    collectorToken: collectorTokenInput.value.trim(),
    sourceLabel: sourceLabelInput.value.trim() || "NovaCart production collector",
  };
}

function persistConfig() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(getConfig()));
  setStatus("Collector configuration saved locally.");
  addLogEntry("Configuration updated", "NovaCart saved the API base, collector token, and source label.");
}

function loadConfig() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return;
    }
    const config = JSON.parse(raw);
    apiBaseInput.value = config.apiBase || apiBaseInput.value;
    collectorTokenInput.value = config.collectorToken || "";
    sourceLabelInput.value = config.sourceLabel || sourceLabelInput.value;
    setStatus(config.collectorToken ? "Collector token loaded. Ready to send telemetry." : "Paste your collector token to begin.");
  } catch (_error) {
    setStatus("Could not load saved collector configuration.");
  }
}

function setStatus(message, tone = "neutral") {
  collectorStatus.textContent = message;
  collectorStatus.style.color =
    tone === "success" ? "#198754" : tone === "error" ? "#d34d32" : tone === "warn" ? "#b66d05" : "#1d1a16";
}

function addLogEntry(title, message) {
  const empty = activityLog.querySelector(".activity-empty");
  if (empty) {
    empty.remove();
  }
  const node = document.createElement("div");
  node.className = "activity-entry";
  node.innerHTML = `<strong>${title}</strong><p>${message}</p>`;
  activityLog.prepend(node);
}

function ensureConfigured() {
  const config = getConfig();
  if (!config.apiBase || !config.collectorToken) {
    setStatus("Missing API base or collector token.", "error");
    addLogEntry("Collector blocked", "Paste the collector token from the CyberAgent dashboard before sending telemetry.");
    return null;
  }
  return config;
}

async function sendScenario(title, payloadDescription, payload) {
  const config = ensureConfigured();
  if (!config) {
    return;
  }

  setStatus("Sending telemetry to CyberAgent...", "warn");
  try {
    const response = await fetch(`${config.apiBase}/collector/ingest`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Collector-Token": config.collectorToken,
      },
      body: JSON.stringify({
        source_label: config.sourceLabel,
        ...payload,
      }),
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || "Collector ingestion failed");
    }

    const suffix = data.attack_id ? ` Incident id: ${data.attack_id}.` : "";
    setStatus(`Telemetry accepted by CyberAgent.${suffix}`, "success");
    addLogEntry(title, `${payloadDescription} ${data.events_ingested} event(s) were accepted by CyberAgent.${suffix}`);
  } catch (error) {
    setStatus("Failed to send telemetry to CyberAgent.", "error");
    addLogEntry(title, `Request failed: ${error.message}`);
  }
}

function healthyTrafficPayload() {
  const srcIp = "198.51.100.24";
  return {
    run_detection: false,
    events: [
      accessEvent(srcIp, "/"),
      accessEvent(srcIp, "/products"),
      accessEvent(srcIp, "/pricing"),
      accessEvent(srcIp, "/checkout", "POST", 200, "novacart-browser", 920),
    ],
  };
}

function bruteForcePayload() {
  const srcIp = "198.51.100.77";
  return {
    run_detection: true,
    events: [
      ...Array.from({ length: 12 }, () => authEvent(srcIp, "admin", "FAILED")),
      ...Array.from({ length: 8 }, () => networkEvent(srcIp, TARGET_IP, 22, 140, 4500, "ACK")),
      accessEvent(srcIp, "/admin/login", "POST", 401, "credential-checker", 742),
    ],
  };
}

function reconPayload() {
  const srcIp = "203.0.113.18";
  const paths = ["/admin", "/admin/login", "/.env", "/config.php", "/server-status", "/backup.zip", "/wp-admin"];
  return {
    run_detection: true,
    events: [
      ...paths.map((path) => accessEvent(srcIp, path, "GET", 403, "recon-bot", 220)),
      ...paths.map(() => networkEvent(srcIp, TARGET_IP, 443, randInt(10, 24), randInt(700, 1400), "SYN")),
    ],
  };
}

function trafficPayload() {
  const sources = Array.from({ length: 12 }, (_, index) => `203.0.113.${20 + index}`);
  return {
    run_detection: true,
    events: [
      ...Array.from({ length: 28 }, (_, index) => {
        const src = sources[index % sources.length];
        const path = ["/", "/products", "/login", "/api/search"][index % 4];
        return accessEvent(src, path, "GET", 200, "loadbot", randInt(1000, 2000));
      }),
      ...Array.from({ length: 28 }, (_, index) => {
        const src = sources[index % sources.length];
        return networkEvent(src, TARGET_IP, 443, randInt(5000, 9000), randInt(250000, 480000), "SYN");
      }),
    ],
  };
}

function customerLoginPayload(email) {
  const srcIp = "198.51.100.24";
  return {
    run_detection: false,
    events: [
      accessEvent(srcIp, "/login", "GET", 200, "novacart-browser", 688),
      accessEvent(srcIp, "/login", "POST", 200, "novacart-browser", 844),
      {
        ...authEvent(srcIp, email || "customer@novacart.io", "SUCCESS", 443),
        port: 443,
        message: `${isoNow()} AUTH service=app src=${srcIp} user=${email || "customer@novacart.io"} result=SUCCESS port=443`,
      },
    ],
  };
}

document.getElementById("saveConfigBtn").addEventListener("click", persistConfig);
document.getElementById("sendHealthBtn").addEventListener("click", () =>
  sendScenario("Healthy traffic", "NovaCart generated healthy browsing telemetry.", healthyTrafficPayload())
);
document.getElementById("browseBtn").addEventListener("click", () =>
  sendScenario("Product browse", "A normal customer session viewed products and storefront pages.", healthyTrafficPayload())
);
document.getElementById("checkoutBtn").addEventListener("click", () =>
  sendScenario("Checkout flow", "A normal checkout flow was collected and forwarded.", {
    run_detection: false,
    events: [
      accessEvent("198.51.100.24", "/products"),
      accessEvent("198.51.100.24", "/cart", "POST", 200, "novacart-browser", 780),
      accessEvent("198.51.100.24", "/checkout", "POST", 200, "novacart-browser", 920),
      networkEvent("198.51.100.24", TARGET_IP, 443, 38, 6200, "ACK"),
    ],
  })
);

document.querySelectorAll("[data-scenario='browse']").forEach((button) => {
  button.addEventListener("click", () =>
    sendScenario("Product page visit", "A customer opened a product page on NovaCart.", healthyTrafficPayload())
  );
});

document.querySelector("[data-scenario='healthy']").addEventListener("click", () =>
  sendScenario("Healthy traffic", "NovaCart generated healthy browsing telemetry.", healthyTrafficPayload())
);
document.querySelector("[data-scenario='bruteforce']").addEventListener("click", () =>
  sendScenario("Brute force simulation", "NovaCart observed repeated failed administrator logins.", bruteForcePayload())
);
document.querySelector("[data-scenario='recon']").addEventListener("click", () =>
  sendScenario("Recon simulation", "NovaCart observed sensitive-path reconnaissance traffic.", reconPayload())
);
document.querySelector("[data-scenario='traffic']").addEventListener("click", () =>
  sendScenario("Traffic spike simulation", "NovaCart observed a sudden traffic spike and SYN-heavy network burst.", trafficPayload())
);

document.getElementById("customerLoginForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const email = document.getElementById("customerEmail").value.trim();
  sendScenario("Customer login", "A normal customer login was collected by the site-side agent.", customerLoginPayload(email));
});

document.getElementById("adminLoginForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const adminUser = document.getElementById("adminUser").value.trim() || "admin";
  sendScenario(
    "Admin login attempt",
    `The admin portal generated suspicious login telemetry for user ${adminUser}.`,
    bruteForcePayload()
  );
});

document.getElementById("clearLogBtn").addEventListener("click", () => {
  activityLog.innerHTML = '<div class="activity-empty">No site-side collector events sent yet.</div>';
});

loadConfig();
if (!activityLog.children.length) {
  activityLog.innerHTML = '<div class="activity-empty">No site-side collector events sent yet.</div>';
}
