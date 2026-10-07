document.addEventListener('DOMContentLoaded', async () => {
    const scanId = window.SCAN_ID;

    if (!scanId) {
        alert("No scan ID provided.");
        return;
    }

    try {
        const response = await fetch(`/api/scan/${scanId}/results`);
        if (!response.ok) throw new Error("Failed to fetch results");

        const data = await response.json();

        if (data.status !== "completed") {
            document.querySelector('#loadingState').innerHTML = `
                <i class="fas fa-exclamation-triangle text-red-500 text-5xl mb-4"></i>
                <p style="color:var(--text-primary); font-family: var(--font-mono);">Scan is ${data.status.toUpperCase()}</p>
                <a href="/" style="color:var(--neon-green); text-decoration:none; margin-top:20px; display:inline-block;">RETURN HOME</a>
            `;
            return;
        }

        renderDashboard(data);

    } catch (error) {
        document.querySelector('#loadingState').innerHTML = `
            <p style="color:#ef4444; font-family:var(--font-mono);">Error loading results: ${error.message}</p>
        `;
    }
});

const SEV_MAP = {
    CRITICAL: { class: 'critical', hex: '#ef4444', order: 5 },
    HIGH: { class: 'high', hex: '#f97316', order: 4 },
    MEDIUM: { class: 'medium', hex: '#eab308', order: 3 },
    LOW: { class: 'low', hex: '#38bdf8', order: 2 },
    INFO: { class: 'info', hex: '#9ca3af', order: 1 }
};

function renderDashboard(data) {
    document.querySelector('#loadingState').classList.add('hidden');
    document.querySelector('#dashboardContent').classList.remove('hidden');

    document.querySelector('#targetUrlText').textContent = data.url;
    document.querySelector('#scanStatusBadge').textContent = data.status;

    let targetScore = data.score || 0;
    
    // Grade Colorization
    const gradeEl = document.querySelector('#gradeDisplay');
    gradeEl.textContent = `Grade: ${data.grade || '-'}`;
    gradeEl.className = "score-grade"; // reset
    if (["A", "B"].includes(data.grade)) gradeEl.classList.add('grade-a');
    else if (data.grade === "C") gradeEl.style.color = "var(--neon-blue)";
    else if (data.grade === "D") gradeEl.style.color = "#f97316";
    else gradeEl.classList.add('grade-f');

    // Make summary text pretty
    let summaryHtml = data.summary || '';
    summaryHtml = summaryHtml.replace(/\b(critical|high|medium|low|info)\b/gi, match => {
        return `<span style="font-weight:bold; color:${SEV_MAP[match.toUpperCase()]?.hex || 'inherit'}">${match}</span>`;
    });
    document.querySelector('#summaryText').innerHTML = summaryHtml;

    const resultsJson = data.results_json;
    if (!resultsJson) return;

    // Findings count mapping
    const findingCounts = resultsJson.score_data.findings_count || {};
    // Normalize casing from backend
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    Object.entries(findingCounts).forEach(([k, v]) => {
        const key = k.toUpperCase();
        if (counts[key] !== undefined) counts[key] = v;
    });

    renderFindingsCounts(counts);
    renderChartAndScore(counts, targetScore);

    // Extract all findings across all modules
    let allFindings = [];
    let modulesSummary = [];
    const pdfDataModules = resultsJson.pdf_data.modules || {};

    Object.entries(pdfDataModules).forEach(([modName, findingsArr], modIndex) => {
        const niceName = modName.replace(/_/g, " ").toUpperCase();
        let maxSevOrder = 0;
        let modSev = 'clean';
        let findingCount = 0;

        if (findingsArr && findingsArr.length > 0) {
            findingsArr.forEach((f, fIdx) => {
                const sevLevel = (f.Severity || 'INFO').toUpperCase();
                const sevOrder = SEV_MAP[sevLevel]?.order || 0;
                if (sevOrder > maxSevOrder) maxSevOrder = sevOrder;

                // Parse structured payload / parameter / URL out of description
                const rawDesc = f.Description || '';
                let paramVal = null, payloadVal = null, urlVal = null, evidenceVal = null;

                const paramMatch = rawDesc.match(/[Pp]aram(?:eter)?\s*[`'"]?([\w\-]+)[`'"]?\s*(?:vulnerable|exposed|reflects)/i);
                if (paramMatch) paramVal = paramMatch[1];

                const payloadMatch = rawDesc.match(/payload\s+([^,\.]+)/i);
                if (payloadMatch) payloadVal = payloadMatch[1].trim();

                const urlMatch = rawDesc.match(/(?:at|url)\s+(https?:\/\/[^\s,]+)/i);
                if (urlMatch) urlVal = urlMatch[1].trim();

                if (rawDesc.toLowerCase().includes('error') || rawDesc.toLowerCase().includes('cve') || rawDesc.toLowerCase().includes('evidence')) {
                    evidenceVal = rawDesc;
                }

                allFindings.push({
                    id: `${modIndex}_${fIdx}`,
                    title: f.Finding || 'Unknown Vulnerability',
                    module: niceName,
                    severity: sevLevel,
                    description: rawDesc,
                    recommendation: f.Recommendation || '',
                    owasp: f.owasp_id || null,
                    owaspName: f.owasp_name || null,
                    paramVal, payloadVal, urlVal, evidenceVal
                });
                findingCount++;
            });
        }

        if (maxSevOrder >= 4) modSev = 'vuln';
        else if (maxSevOrder >= 2) modSev = 'warn';

        modulesSummary.push({
            name: niceName,
            status: modSev,
            findings: findingCount,
            note: findingCount > 0 ? `${findingCount} findings` : 'Clean'
        });
    });

    // Sort findings: CRITICAL first, then by module alphabetically within same severity
    allFindings.sort((a, b) => {
        const sevDiff = (SEV_MAP[b.severity]?.order || 0) - (SEV_MAP[a.severity]?.order || 0);
        if (sevDiff !== 0) return sevDiff;
        return a.module.localeCompare(b.module);
    });

    renderFindingsList(allFindings);
    renderModulesList(modulesSummary);

    if (resultsJson.pdf_data.owasp_summary) {
        renderOwaspSummary(resultsJson.pdf_data.owasp_summary);
    }
}

function renderFindingsCounts(counts) {
    const findingBarsContainer = document.getElementById('findingBars');
    const totalFindings = Object.values(counts).reduce((a, b) => a + b, 0);
    
    findingBarsContainer.innerHTML = Object.entries(counts).map(([sev, c]) => `
        <div class="breakdown-row">
            <div class="badge badge-${SEV_MAP[sev].class}">${sev}</div>
            <div class="bar-track">
                <div class="bar-fill bg-${SEV_MAP[sev].class}" style="width: ${totalFindings ? (c/totalFindings)*100 : 0}%"></div>
            </div>
            <div class="breakdown-count">${c}</div>
        </div>
    `).join('');
}

function renderChartAndScore(counts, targetScore) {
    const severityChartCtx = document.getElementById('severityChart');
    const scoreArc = document.getElementById('scoreArc');
    const scoreDisplay = document.getElementById('scoreDisplay');
    const scoreRingNum = document.getElementById('scoreRingNum');

    // Chart.js
    new Chart(severityChartCtx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(counts),
            datasets: [{
                data: Object.values(counts),
                backgroundColor: Object.values(SEV_MAP).map(m => m.hex),
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            cutout: '75%',
            plugins: { legend: { display: false } },
            animation: { duration: 1500, easing: 'easeOutQuart' },
            layout: { padding: 0 }
        }
    });

    // Determine target color based on grade/score
    let ringColor = '#ef4444';
    if (targetScore >= 90) ringColor = '#00ff41';
    else if (targetScore >= 70) ringColor = '#eab308';
    else if (targetScore >= 60) ringColor = '#f97316';
    scoreArc.setAttribute('stroke', ringColor);

    setTimeout(() => {
        scoreArc.setAttribute('stroke-dasharray', `${targetScore} 100`);
    }, 100);

    const animationDuration = 1500;
    let startTimestamp = null;
    const animateScore = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / animationDuration, 1);
        const easeOutQuart = 1 - Math.pow(1 - progress, 4);
        const currentScore = Math.floor(easeOutQuart * targetScore);
        
        scoreDisplay.textContent = currentScore;
        scoreRingNum.textContent = currentScore;
        
        if (progress < 1) {
            requestAnimationFrame(animateScore);
        } else {
            scoreDisplay.textContent = targetScore;
            scoreRingNum.textContent = targetScore;
        }
    };
    requestAnimationFrame(animateScore);
}

const SEV_ICONS = {
    CRITICAL: 'fa-skull-crossbones',
    HIGH: 'fa-fire',
    MEDIUM: 'fa-exclamation-triangle',
    LOW: 'fa-info-circle',
    INFO: 'fa-circle-info'
};

let _allFindings = [];
let _activeFilter = 'ALL';

function renderFindingsList(findings) {
    _allFindings = findings;
    _activeFilter = 'ALL';

    const wrapper = document.getElementById('findingsContainer');

    // Build severity counts for filter pills
    const sevCounts = { ALL: findings.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach(f => { if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++; });

    // Filter pills row
    const filterPills = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(sev => {
        const cls = sev === 'ALL' ? 'pill-all' : `badge-${SEV_MAP[sev]?.class || 'info'}`;
        const count = sevCounts[sev] || 0;
        return `<button class="filter-pill ${sev === 'ALL' ? 'active' : ''}" data-sev="${sev}" onclick="filterFindings('${sev}', this)">
            <span>${sev}</span><span class="pill-count">${count}</span>
        </button>`;
    }).join('');

    wrapper.innerHTML = `
        <div class="findings-filter-bar" id="findingsFilterBar">${filterPills}</div>
        <div class="findings-list" id="findingsList"></div>
    `;

    renderFilteredFindings(findings);
}

function filterFindings(sev, btn) {
    _activeFilter = sev;
    document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    const filtered = sev === 'ALL' ? _allFindings : _allFindings.filter(f => f.severity === sev);
    renderFilteredFindings(filtered);
}

function renderFilteredFindings(findings) {
    const list = document.getElementById('findingsList');
    if (!list) return;

    if (findings.length === 0) {
        list.innerHTML = `
            <div class="findings-empty">
                <i class="fas fa-check-circle" style="font-size:2.5rem; color:var(--neon-green); margin-bottom:1rem;"></i>
                <p>No findings for this severity level.</p>
            </div>`;
        return;
    }

    list.innerHTML = findings.map(f => {
        const sevCls = SEV_MAP[f.severity]?.class || 'info';
        const sevHex = SEV_MAP[f.severity]?.hex || '#9ca3af';
        const sevIcon = SEV_ICONS[f.severity] || 'fa-circle-info';

        // Build detail rows — only show fields that have actual values
        let detailRows = '';

        if (f.description && f.description !== '-') {
            detailRows += `
                <div class="detail-row">
                    <div class="detail-label"><i class="fas fa-align-left"></i> Description</div>
                    <div class="detail-val">${escHtml(f.description)}</div>
                </div>`;
        }

        if (f.paramVal) {
            detailRows += `
                <div class="detail-row">
                    <div class="detail-label"><i class="fas fa-tag"></i> Vulnerable Parameter</div>
                    <div class="detail-val"><code class="inline-code">${escHtml(f.paramVal)}</code></div>
                </div>`;
        }

        if (f.payloadVal) {
            detailRows += `
                <div class="detail-row">
                    <div class="detail-label"><i class="fas fa-bug"></i> Attack Payload</div>
                    <div class="detail-val"><pre class="payload-pre">${escHtml(f.payloadVal)}</pre></div>
                </div>`;
        }

        if (f.urlVal) {
            detailRows += `
                <div class="detail-row">
                    <div class="detail-label"><i class="fas fa-link"></i> Affected URL</div>
                    <div class="detail-val"><code class="inline-code url-code">${escHtml(f.urlVal)}</code></div>
                </div>`;
        }

        if (f.evidenceVal && !f.description?.includes(f.evidenceVal)) {
            detailRows += `
                <div class="detail-row">
                    <div class="detail-label"><i class="fas fa-microscope"></i> Evidence</div>
                    <div class="detail-val evidence-text">${escHtml(f.evidenceVal)}</div>
                </div>`;
        }

        const owaspBadge = f.owasp
            ? `<span class="owasp-ref-badge" title="${f.owaspName || f.owasp}">${f.owasp}</span>`
            : '';

        const recRow = f.recommendation && f.recommendation !== '-'
            ? `<div class="finding-rec-box">
                    <div class="rec-label"><i class="fas fa-wrench"></i> Remediation</div>
                    <p>${escHtml(f.recommendation)}</p>
               </div>`
            : '';

        return `
        <div class="finding-item sev-border-${sevCls}" id="fi_${f.id}">
            <div class="finding-header" onclick="toggleFinding('${f.id}')">
                <div class="sev-icon-wrap" style="background:${sevHex}18; border:1px solid ${sevHex}44;">
                    <i class="fas ${sevIcon}" style="color:${sevHex}"></i>
                </div>
                <div class="finding-header-body">
                    <div class="finding-title">${escHtml(f.title)}</div>
                    <div class="finding-meta">
                        <span class="finding-module-tag"><i class="fas fa-cube"></i>${f.module}</span>
                        ${owaspBadge}
                    </div>
                </div>
                <div class="badge badge-${sevCls}">${f.severity}</div>
                <i class="fas fa-chevron-down chevron" id="chev_${f.id}"></i>
            </div>
            <div class="finding-details" id="det_${f.id}">
                <div class="finding-detail-body">
                    ${detailRows || '<div class="detail-row"><div class="detail-val" style="color:var(--text-muted)">No additional detail available.</div></div>'}
                    ${recRow}
                </div>
            </div>
        </div>`;
    }).join('');
}

function escHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function renderModulesList(modules) {
    const modIconMap = {
        vuln: { color: '#ef4444', ico: 'fa-exclamation-circle' },
        warn: { color: '#eab308', ico: 'fa-exclamation-triangle' },
        clean: { color: 'var(--neon-green)', ico: 'fa-check-circle' }
    };
    
    const icoMapByName = {
        "PORT SCANNER": "fa-network-wired",
        "SECURITY HEADERS": "fa-heading",
        "SSL/TLS": "fa-lock",
        "DNS RECON": "fa-server",
        "CRAWLER": "fa-spider",
        "XSS": "fa-code",
        "SQL INJECTION": "fa-database",
        "CSRF DETECTION": "fa-exchange-alt",
        "OPEN REDIRECT": "fa-external-link-alt",
        "TECH FINGERPRINTING": "fa-fingerprint",
        "JAVASCRIPT ANALYSIS": "fa-js",
        "WAF DETECTION": "fa-shield-alt"
    };

    document.getElementById('modulesContainer').innerHTML = modules.map(m => {
        let baseIco = icoMapByName[m.name] || 'fa-cube';
        let statusObj = modIconMap[m.status] || modIconMap.clean;
        
        return `
            <div class="mod-card">
                <div class="mod-icon"><i class="fas ${baseIco}"></i></div>
                <div class="mod-info" style="flex:1;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <h4>${m.name}</h4>
                        <i class="fas ${statusObj.ico}" style="color:${statusObj.color}"></i>
                    </div>
                    <div class="note">${m.note}</div>
                    <div class="vuln-count ${m.findings > 0 ? 'count-red' : 'count-gray'}">${m.findings} finding${m.findings !== 1 ? 's' : ''}</div>
                </div>
            </div>
        `;
    }).join('');
}

function renderOwaspSummary(owaspData) {
    document.getElementById('owaspContainer').innerHTML = Object.entries(owaspData).map(([catId, data]) => {
        const severity = data.highest_severity ? data.highest_severity.toUpperCase() : 'INFO';
        const hasFindings = data.count > 0;
        const colorClass = hasFindings ? (SEV_MAP[severity]?.class || 'info') : 'info';

        return `
            <div class="owasp-card border-${colorClass}" style="${!hasFindings ? 'opacity:0.4' : ''}">
                <div class="owasp-header">
                    <span class="owasp-id">${catId}</span>
                    <span class="badge badge-${colorClass}">${hasFindings ? severity : 'CLEAN'}</span>
                </div>
                <h4>${data.name}</h4>
                <div class="owasp-count-num" style="color: ${hasFindings ? SEV_MAP[severity]?.hex : 'inherit'}">${data.count}</div>
                <div style="font-size:0.8rem; color:var(--text-muted); margin-top:5px;">finding${data.count !== 1 ? 's' : ''} mapped</div>
            </div>
        `;
    }).join('');
}

// Helpers
window.toggleFinding = function(id) {
    const det = document.getElementById('det_' + id);
    const chev = document.getElementById('chev_' + id);
    if (!det || !chev) return;
    
    const isExpanded = det.classList.toggle('expanded');
    chev.style.transform = isExpanded ? 'rotate(180deg)' : 'translateZ(0)';
};

const tabsState = {
    contents: null,
    buttons: null
};

window.switchTab = function(tabId, btn) {
    if (!tabsState.contents) {
        tabsState.contents = document.querySelectorAll('.tab-content');
        tabsState.buttons = document.querySelectorAll('.tab-btn');
    }
    
    tabsState.contents.forEach(c => c.classList.remove('active'));
    tabsState.buttons.forEach(b => b.classList.remove('active'));
    
    document.getElementById('tab-' + tabId).classList.add('active');
    btn.classList.add('active');
};
