/* ============================================================
   Guardian SIEM v2.0 — Dashboard JavaScript
   Real-time event feed, charts, MITRE heatmap, and WebSocket
   ============================================================ */

// --- 1. Universal Multi-Project Logic ---
// This hooks into the browser URL and the global fetch function
const urlParams = new URLSearchParams(window.location.search);
const projectFilter = urlParams.get('project') || '';

const originalFetch = window.fetch;
window.fetch = function() {
    let url = arguments[0];
    if (typeof url === 'string' && url.includes('/api/') && projectFilter) {
        const separator = url.includes('?') ? '&' : '?';
        arguments[0] = `${url}${separator}project=${encodeURIComponent(projectFilter)}`;
    }
    return originalFetch.apply(this, arguments);
};

// --- 2. Global State ---
let allEvents = [];
let currentFilter = "ALL";
let socket = null;
let isConnected = false;

// --- 3. Initialization ---
document.addEventListener("DOMContentLoaded", () => {
    initWebSocket();
    fetchStats();
    fetchEvents();
    fetchRules();
    fetchMitre();

    // Auto-refresh fallback (polls every 10s if WebSocket lags)
    setInterval(() => {
        fetchStats();
        fetchEvents();
    }, 10000);
});

// --- 4. WebSocket for Real-Time Updates ---
function initWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    let wsUrl = `${protocol}//${window.location.host}/ws`;
    
    if (projectFilter) {
        wsUrl += `?project=${encodeURIComponent(projectFilter)}`;
    }

    try {
        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
            isConnected = true;
            updateConnectionStatus(true);
            console.log(`[Guardian] Connected to Context: ${projectFilter || 'GLOBAL'}`);
        };

        socket.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === "new_event") {
                const eventProj = data.event.project || 'Default';
                // Isolation check: only show if it matches current project view
                if (!projectFilter || eventProj === projectFilter) {
                    addEventToFeed(data.event);
                    fetchStats(); 
                }
            } else if (data.type === "stats_update") {
                updateStats(data.stats);
            }
        };

        socket.onclose = () => {
            isConnected = false;
            updateConnectionStatus(false);
            console.log("[Guardian] WebSocket disconnected, retrying in 5s...");
            setTimeout(initWebSocket, 5000);
        };

        socket.onerror = (err) => {
            isConnected = false;
            updateConnectionStatus(false);
            console.error("[Guardian] WebSocket Error:", err);
        };
    } catch (e) {
        console.log("[Guardian] WebSocket Init Failed, using polling fallback");
        updateConnectionStatus(false);
    }
}

function updateConnectionStatus(connected) {
    const dot = document.getElementById("status-dot");
    const text = document.getElementById("status-text");
    if (dot && text) {
        dot.className = connected ? "status-dot" : "status-dot offline";
        text.textContent = connected ? "Live" : "Polling";
    }
}

// --- 5. Data Fetching Functions ---
async function fetchStats() {
    try {
        const resp = await fetch("/api/stats");
        const stats = await resp.json();
        updateStats(stats);
    } catch (e) {
        console.error("Failed to fetch stats:", e);
    }
}

async function fetchEvents(filter) {
    try {
        let url = "/api/events?limit=100";
        if (filter && filter !== "ALL") {
            url += `&severity=${filter}`;
        }
        const resp = await fetch(url);
        allEvents = await resp.json();
        renderEventsFeed(allEvents);
    } catch (e) {
        console.error("Failed to fetch events:", e);
    }
}

async function fetchMitre() {
    try {
        const resp = await fetch("/api/mitre");
        const data = await resp.json();
        renderMitreHeatmap(data);
    } catch (e) {
        console.error("Failed to fetch MITRE data:", e);
    }
}

async function fetchRules() {
    try {
        const resp = await fetch("/api/rules");
        const rules = await resp.json();
        renderRulesTable(rules);
    } catch (e) {
        console.error("Failed to fetch rules:", e);
    }
}

// --- 6. UI Rendering Functions ---
function updateStats(stats) {
    setStatValue("stat-total", stats.total_events || 0);
    setStatValue("stat-last24h", stats.last_24h || 0);
    setStatValue("stat-critical", (stats.by_severity || {}).CRITICAL || 0);
    setStatValue("stat-high", (stats.by_severity || {}).HIGH || 0);
    setStatValue("stat-unique-ips", stats.unique_ips || 0);
    setStatValue("stat-last-hour", stats.last_hour || 0);

    updateSeverityChart(stats.by_severity || {});
    updateSourcesList(stats.by_source || {});
}

function setStatValue(id, value) {
    const el = document.getElementById(id);
    if (el) {
        el.textContent = typeof value === "number" ? value.toLocaleString() : value;
    }
}

function addEventToFeed(event) {
    allEvents.unshift(event);
    if (allEvents.length > 200) allEvents = allEvents.slice(0, 200);
    if (currentFilter === "ALL" || event.severity === currentFilter) {
        renderEventsFeed(allEvents);
    }
}

function renderEventsFeed(events) {
    const container = document.getElementById("events-feed");
    if (!container) return;

    const filtered = currentFilter === "ALL" 
        ? events 
        : events.filter(e => e.severity === currentFilter);

    container.innerHTML = filtered.slice(0, 100).map(e => `
        <div class="event-item">
            <div><span class="event-severity ${e.severity}">${e.severity}</span></div>
            <div>
                <div class="event-source">
                    <span class="project-tag" style="color: var(--accent-cyan); font-weight: bold; font-size: 10px; border: 1px solid #333; padding: 1px 4px; border-radius: 3px; margin-right: 5px;">
                        ${escapeHtml(e.project || 'Wyde').toUpperCase()}
                    </span>
                    ${escapeHtml(e.source)}
                    ${e.mitre_id ? `<span class="event-mitre">${escapeHtml(e.mitre_id)}</span>` : ""}
                </div>
                <div class="event-message">${escapeHtml(e.message || "").substring(0, 300)}</div>
                ${e.src_ip ? `<div style="color: var(--text-muted); font-size: 11px; margin-top: 2px;">
                    IP: ${escapeHtml(e.src_ip)}
                    ${e.geo_country ? ` — ${escapeHtml(e.geo_city || "")}, ${escapeHtml(e.geo_country)}` : ""}
                </div>` : ""}
            </div>
            <div class="event-time">${formatTime(e.timestamp)}</div>
        </div>
    `).join("");
}

function updateSeverityChart(bySeverity) {
    const container = document.getElementById("severity-chart");
    if (!container) return;
    const severities = ["CRITICAL", "HIGH", "WARNING", "MEDIUM", "LOW", "INFO"];
    const total = Object.values(bySeverity).reduce((a, b) => a + b, 0) || 1;
    container.innerHTML = severities.filter(s => (bySeverity[s] || 0) > 0).map(s => {
        const count = bySeverity[s] || 0;
        const pct = Math.max((count / total) * 100, 2);
        return `
            <div class="severity-bar-row">
                <span class="severity-bar-label">${s}</span>
                <div class="severity-bar-track"><div class="severity-bar-fill ${s}" style="width: ${pct}%">${count}</div></div>
            </div>`;
    }).join("");
}

function updateSourcesList(bySources) {
    const container = document.getElementById("sources-list");
    if (!container) return;
    const entries = Object.entries(bySources).sort((a, b) => b[1] - a[1]);
    container.innerHTML = entries.map(([source, count]) => `
        <div style="display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid rgba(45,55,72,0.3); font-size:13px;">
            <span style="color:var(--accent-cyan)">${escapeHtml(source)}</span>
            <span style="color:var(--text-muted)">${count.toLocaleString()}</span>
        </div>`).join("");
}

function renderMitreHeatmap(data) {
    const container = document.getElementById("mitre-heatmap");
    if (!container) return;
    const techniques = data.techniques || {};
    const topMitre = data.top_triggered || {};
    const entries = Object.entries(techniques);
    if (entries.length === 0) {
        container.innerHTML = '<div style="color:var(--text-muted); padding:20px; text-align:center;">No MITRE data for this project view.</div>';
        return;
    }
    container.innerHTML = entries.map(([tid, info]) => {
        const hits = topMitre[tid] || 0;
        return `
            <div class="mitre-cell ${hits > 5 ? 'hot' : ''}" title="${info.description || ''}">
                <div class="technique-id">${escapeHtml(tid)}</div>
                <div class="technique-name">${escapeHtml(info.name || '')}</div>
                <div class="hit-count">${hits}</div>
            </div>`;
    }).join("");
}

function renderRulesTable(rules) {
    const container = document.getElementById("rules-table-body");
    if (!container) return;
    container.innerHTML = rules.map(r => `
        <tr>
            <td><span class="event-severity ${r.severity}">${r.severity}</span></td>
            <td>${escapeHtml(r.name)}</td>
            <td><span class="event-mitre">${escapeHtml(r.mitre_id || 'N/A')}</span></td>
            <td style="color:var(--text-secondary); max-width:300px;">${escapeHtml(r.description || '')}</td>
        </tr>`).join("");
}

// --- 7. Utility Functions ---
function setFilter(severity) {
    currentFilter = severity;
    document.querySelectorAll(".filter-btn").forEach(btn => {
        btn.classList.toggle("active", btn.dataset.filter === severity);
    });
    fetchEvents(severity);
}

function escapeHtml(text) {
    if (!text) return "";
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

function formatTime(isoString) {
    if (!isoString) return "";
    try {
        const date = new Date(isoString);
        const now = new Date();
        const diffSec = Math.floor((now - date) / 1000);
        if (diffSec < 60) return `${diffSec}s ago`;
        if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
        if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
        return date.toLocaleDateString() + " " + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch { return isoString; }
}