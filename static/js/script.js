/**
 * script.js — Phishing Detection System Frontend Logic
 * ======================================================
 * Handles:
 * - URL submission and API communication
 * - Result rendering
 * - History management
 * - Chart rendering (Chart.js)
 * - Example URL population
 * - Security: Output encoding to prevent XSS
 *
 * CNS Concept: Client-side input validation (first layer)
 * Server-side validation (second layer) is in app.py
 *
 * Author: Phishing Detection System
 * Project: Computer and Network Security (CNS) College Project
 */

"use strict";

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

/**
 * CNS Security: Escape HTML to prevent XSS when inserting user data into DOM.
 * Never use innerHTML with untrusted data without escaping!
 */
function escapeHtml(str) {
    if (typeof str !== "string") return String(str);
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/** Show a toast notification */
function showToast(message, type = "info") {
    const toast = document.getElementById("toast");
    if (!toast) return;
    const icons = { info: "ℹ️", success: "✅", error: "❌", warning: "⚠️" };
    toast.innerHTML = `<span>${icons[type] || "ℹ️"}</span><span>${escapeHtml(message)}</span>`;
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 3500);
}

/** Show/hide loading overlay */
function setLoading(visible) {
    const overlay = document.getElementById("loaderOverlay");
    if (overlay) {
        overlay.classList.toggle("show", visible);
    }
}

/** Get risk level display info */
function getRiskInfo(level, score) {
    const map = {
        LOW: {
            icon: "🟢",
            title: "LIKELY SAFE",
            class: "low",
            label: "Low Risk",
        },
        SUSPICIOUS: {
            icon: "🟡",
            title: "SUSPICIOUS URL",
            class: "suspicious",
            label: "Suspicious",
        },
        HIGH: {
            icon: "🔴",
            title: "HIGH RISK — LIKELY PHISHING",
            class: "high",
            label: "High Risk",
        },
    };
    return map[level] || map["SUSPICIOUS"];
}

/** Format a date string nicely */
function formatDate(dateStr) {
    if (!dateStr) return "—";
    try {
        const d = new Date(dateStr.replace(" ", "T"));
        return d.toLocaleString("en-IN", {
            day: "2-digit", month: "short", year: "numeric",
            hour: "2-digit", minute: "2-digit"
        });
    } catch {
        return dateStr;
    }
}

// ============================================================
// MOBILE MENU
// ============================================================
function initMobileMenu() {
    const btn = document.getElementById("mobileMenuBtn");
    const nav = document.getElementById("navbarNav");
    if (!btn || !nav) return;
    btn.addEventListener("click", () => {
        nav.classList.toggle("open");
    });
    // Close on outside click
    document.addEventListener("click", (e) => {
        if (!btn.contains(e.target) && !nav.contains(e.target)) {
            nav.classList.remove("open");
        }
    });
}

// ============================================================
// URL ANALYSIS — MAIN LOGIC
// ============================================================

/**
 * Submit URL for analysis.
 * CNS Concept: Client-side validation before server-side validation.
 * Defense in depth: both layers validate the input.
 */
async function analyzeUrl() {
    const input = document.getElementById("urlInput");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const resultSection = document.getElementById("resultSection");

    if (!input) return;

    const url = input.value.trim();

    // Client-side validation (CNS: input validation)
    if (!url) {
        showToast("Please enter a URL to analyze.", "warning");
        input.focus();
        return;
    }

    if (url.length > 2048) {
        showToast("URL is too long. Maximum 2048 characters.", "error");
        return;
    }

    // Disable button and show loader
    if (analyzeBtn) {
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = `<span class="loader-ring" style="width:18px;height:18px;border-width:2px;"></span> Analyzing...`;
    }
    setLoading(true);

    // Hide previous result
    if (resultSection) resultSection.classList.remove("show");

    try {
        // POST to Flask API
        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            body: JSON.stringify({ url }),
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Server returned an error");
        }

        // Render result
        renderResult(data);

        // Smooth scroll to result
        setTimeout(() => {
            if (resultSection) {
                resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
            }
        }, 100);

        // Update stats if on index page
        updateDashboardStats();

    } catch (err) {
        console.error("Analysis error:", err);
        showToast(err.message || "Analysis failed. Is the server running?", "error");
    } finally {
        setLoading(false);
        if (analyzeBtn) {
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = `<span>🔍</span> Analyze URL`;
        }
    }
}

// ============================================================
// RESULT RENDERING
// ============================================================

/** Render the full analysis result into the DOM */
function renderResult(data) {
    const resultSection = document.getElementById("resultSection");
    if (!resultSection) return;

    const riskInfo = getRiskInfo(data.risk_level, data.risk_score);
    const score = data.risk_score || 0;

    // Build risk banner
    const bannerHtml = `
        <div class="risk-banner ${riskInfo.class}">
            <div class="risk-icon-large">${escapeHtml(riskInfo.icon)}</div>
            <div class="risk-info">
                <div class="risk-label">Risk Assessment Result</div>
                <div class="risk-title">${escapeHtml(riskInfo.title)}</div>
                <div class="risk-url">🔗 ${escapeHtml(data.url)}</div>
                <div class="score-bar-container" style="margin-top:12px;max-width:400px;">
                    <div class="score-bar-label">
                        <span>Risk Level</span>
                        <span>${score}/100</span>
                    </div>
                    <div class="score-bar-track">
                        <div class="score-bar-fill" id="scoreBarFill" style="width: 0%"></div>
                    </div>
                </div>
            </div>
            <div class="score-gauge">
                <div class="score-circle">
                    <div class="score-number">${score}</div>
                    <div class="score-label">/ 100</div>
                </div>
                <div style="font-size:0.72rem;color:var(--text-muted);margin-top:6px;">${escapeHtml(riskInfo.label)}</div>
            </div>
        </div>
    `;

    // Build findings
    const reasons  = data.reasons  || [];
    const positives = data.positives || [];

    let reasonsHtml = reasons.length
        ? reasons.map(r => `
            <div class="finding-item reason">
                <span class="finding-icon">⚠️</span>
                <span class="finding-text">${escapeHtml(r)}</span>
            </div>`).join("")
        : `<div class="finding-item positive"><span class="finding-icon">✓</span><span class="finding-text">No suspicious indicators found</span></div>`;

    let positivesHtml = positives.length
        ? positives.map(p => `
            <div class="finding-item positive">
                <span class="finding-icon">✓</span>
                <span class="finding-text">${escapeHtml(p)}</span>
            </div>`).join("")
        : `<div class="finding-item"><span class="finding-text text-muted">No positive indicators recorded</span></div>`;

    const findingsHtml = `
        <div class="findings-grid">
            <div class="findings-card">
                <div class="findings-card-title danger">⚠️ Suspicious Findings</div>
                ${reasonsHtml}
            </div>
            <div class="findings-card">
                <div class="findings-card-title safe">✅ Safe Characteristics</div>
                ${positivesHtml}
            </div>
        </div>
    `;

    // Build analysis table
    const tableRows = (data.analysis_table || []).map(row => {
        const statusMap = {
            safe:    { icon: "✓", label: "Safe",     cls: "safe" },
            warning: { icon: "⚠", label: "Warning",  cls: "warning" },
            danger:  { icon: "✗", label: "Risk",     cls: "danger" },
        };
        const s = statusMap[row.status] || statusMap.safe;
        return `
            <tr>
                <td class="feature-name">${escapeHtml(row.feature)}</td>
                <td><span class="status-badge ${s.cls}">${s.icon} ${s.label}</span></td>
                <td class="feature-detail">${escapeHtml(row.detail || "")}</td>
            </tr>
        `;
    }).join("");

    const tableHtml = `
        <div class="card mb-6">
            <div class="card-title"><span class="icon">📊</span> Detailed Feature Analysis</div>
            <div style="overflow-x:auto;">
                <table class="analysis-table">
                    <thead>
                        <tr>
                            <th>Feature</th>
                            <th>Status</th>
                            <th>Detail</th>
                        </tr>
                    </thead>
                    <tbody>${tableRows}</tbody>
                </table>
            </div>
        </div>
    `;

    // Recommendation
    const recHtml = `
        <div class="recommendation-box">
            <div class="rec-label">💡 Recommendation</div>
            <p>${escapeHtml(data.recommendation || "")}</p>
        </div>
        <div class="disclaimer-box">
            ${escapeHtml(data.disclaimer || "")}
        </div>
    `;

    // Assemble full result
    resultSection.innerHTML = bannerHtml + findingsHtml + tableHtml + recHtml;
    resultSection.classList.add("show");

    // Animate score bar
    setTimeout(() => {
        const fill = document.getElementById("scoreBarFill");
        if (fill) fill.style.width = score + "%";
    }, 200);
}

// ============================================================
// EXAMPLE URLs
// ============================================================

const EXAMPLE_URLS = [
    { url: "https://example.com",                       risk: "low",  label: "example.com (Safe)" },
    { url: "https://google.com",                         risk: "low",  label: "google.com (Safe)" },
    { url: "http://example.com/verify-account-login",    risk: "med",  label: "verify-account (Susp.)" },
    { url: "http://192.168.1.100/login/verify",          risk: "high", label: "IP login (High Risk)" },
    { url: "http://paypal-secure-login.com/update",      risk: "high", label: "Brand spoof (High Risk)" },
    { url: "http://free-bonus-claim.tk/reward",          risk: "high", label: "Suspicious TLD (High)" },
];

/** Fill the URL input with an example URL */
function fillExample(url) {
    const input = document.getElementById("urlInput");
    if (input) {
        input.value = url;
        input.focus();
        // Auto-scroll to input
        input.scrollIntoView({ behavior: "smooth", block: "center" });
    }
}

/** Render example URL tags */
function renderExampleTags() {
    const container = document.getElementById("exampleTags");
    if (!container) return;

    container.innerHTML = EXAMPLE_URLS.map(ex => `
        <button class="example-tag" onclick="fillExample('${escapeHtml(ex.url)}')" title="${escapeHtml(ex.url)}">
            <span class="risk-dot ${ex.risk}"></span>
            ${escapeHtml(ex.label)}
        </button>
    `).join("");
}

// ============================================================
// DASHBOARD STATS
// ============================================================

/** Fetch and update dashboard stats */
async function updateDashboardStats() {
    try {
        const res = await fetch("/api/stats");
        if (!res.ok) return;
        const stats = await res.json();

        const map = {
            statTotal: stats.total || 0,
            statLow:   stats.low   || 0,
            statMed:   stats.suspicious || 0,
            statHigh:  stats.high  || 0,
        };

        Object.entries(map).forEach(([id, val]) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        });

        // Update chart if it exists and is a valid Chart instance
        if (window.riskChart && typeof window.riskChart.update === "function") {
            window.riskChart.data.datasets[0].data = [
                stats.low || 0,
                stats.suspicious || 0,
                stats.high || 0,
            ];
            window.riskChart.update();
        }
    } catch (err) {
        // Non-fatal
    }
}

// ============================================================
// CHART (Dashboard)
// ============================================================

/** Initialize Chart.js donut chart */
function initChart(low, suspicious, high) {
    const canvas = document.getElementById("riskChart");
    if (!canvas || typeof Chart === "undefined") return;

    // Destroy existing chart if any (guard against non-Chart objects)
    if (window.riskChart && typeof window.riskChart.destroy === "function") {
        window.riskChart.destroy();
        window.riskChart = null;
    }

    window.riskChart = new Chart(canvas, {
        type: "doughnut",
        data: {
            labels: ["Low Risk", "Suspicious", "High Risk"],
            datasets: [{
                data: [low || 0, suspicious || 0, high || 0],
                backgroundColor: [
                    "rgba(16, 185, 129, 0.8)",
                    "rgba(245, 158, 11, 0.8)",
                    "rgba(239, 68, 68, 0.8)",
                ],
                borderColor: [
                    "rgba(16, 185, 129, 1)",
                    "rgba(245, 158, 11, 1)",
                    "rgba(239, 68, 68, 1)",
                ],
                borderWidth: 2,
                hoverOffset: 8,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "70%",
            plugins: {
                legend: {
                    position: "bottom",
                    labels: {
                        color: "#8b9db5",
                        padding: 16,
                        font: { size: 12 },
                    },
                },
                tooltip: {
                    callbacks: {
                        label: (ctx) => ` ${ctx.label}: ${ctx.parsed} URLs`,
                    },
                },
            },
        },
    });
}

// ============================================================
// HISTORY PAGE
// ============================================================

/** Clear analysis history */
async function clearHistory() {
    if (!confirm("Clear all URL analysis history? This cannot be undone.")) return;

    try {
        const res = await fetch("/api/history", { method: "DELETE" });
        const data = await res.json();
        showToast(data.message || "History cleared.", "success");
        setTimeout(() => location.reload(), 1200);
    } catch (err) {
        showToast("Failed to clear history.", "error");
    }
}

// ============================================================
// KEYBOARD SHORTCUTS
// ============================================================

document.addEventListener("keydown", function (e) {
    // Enter key in URL input
    if (e.key === "Enter") {
        const input = document.getElementById("urlInput");
        if (document.activeElement === input) {
            analyzeUrl();
        }
    }
    // Ctrl+K or Cmd+K to focus input
    if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        const input = document.getElementById("urlInput");
        if (input) {
            input.focus();
            input.select();
        }
    }
});

// ============================================================
// PAGE INITIALIZATION
// ============================================================

document.addEventListener("DOMContentLoaded", function () {
    initMobileMenu();
    renderExampleTags();

    // Set active nav link based on current page
    const currentPath = window.location.pathname;
    document.querySelectorAll(".navbar-nav a").forEach(link => {
        if (link.getAttribute("href") === currentPath) {
            link.classList.add("active");
        }
    });

    // Auto-fetch and display stats
    updateDashboardStats();

    // Analyze button click
    const analyzeBtn = document.getElementById("analyzeBtn");
    if (analyzeBtn) {
        analyzeBtn.addEventListener("click", analyzeUrl);
    }

    // Chart initialization (if chart data exists in page) — deferred to ensure CDN loaded
    const chartData = window.CHART_DATA;
    if (chartData) {
        setTimeout(() => initChart(chartData.low, chartData.suspicious, chartData.high), 100);
    }

    console.log("%c🛡️ Phishing Detection System", "color:#00d4ff;font-size:16px;font-weight:bold;");
    console.log("%cCNS College Project — Static URL Analysis Engine", "color:#8b9db5;");
    console.log("%c⚠️  This tool performs static analysis only. No URLs are visited.", "color:#f59e0b;");
});
