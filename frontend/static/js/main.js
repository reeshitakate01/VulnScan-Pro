const modulesList = [
    { id: 'waf', name: 'WAF Detection', time: 5, checked: true },
    { id: 'port', name: 'Port Scan', time: 15, checked: true },
    { id: 'xss', name: 'XSS', time: 20, checked: true },
    { id: 'headers', name: 'Security Headers', time: 2, checked: true },
    { id: 'crawler', name: 'Crawler', time: 30, checked: true },
    { id: 'sqli', name: 'SQL Injection', time: 45, checked: true },
    { id: 'ssl', name: 'SSL/TLS', time: 10, checked: true },
    { id: 'dns', name: 'DNS Recon', time: 8, checked: true },
    { id: 'tech', name: 'Tech Fingerprinting', time: 12, checked: true },
    { id: 'js', name: 'JavaScript Analysis', time: 25, checked: true },
    { id: 'redirect', name: 'Open Redirect', time: 18, checked: true },
    { id: 'csrf', name: 'CSRF Detection', time: 22, checked: true },
    { id: 'cors', name: 'CORS', time: 4, checked: true },
    { id: 'methods', name: 'HTTP Methods', time: 4, checked: true },
    { id: 'recon', name: 'Recon', time: 5, checked: true }
];

document.addEventListener('DOMContentLoaded', () => {
    // 1. Inject checkboxes into UI matching new design
    const modulesGrid = document.querySelector('.modules-grid');
    if (modulesGrid) {
        modulesList.forEach(mod => {
            const label = document.createElement('label');
            label.className = 'cyber-checkbox-label';
            label.innerHTML = `
                <input type="checkbox" name="modules" value="${mod.name}" data-time="${mod.time}" class="cyber-checkbox" ${mod.checked ? 'checked' : ''}>
                <div class="checkbox-box"></div>
                <span class="checkbox-text">${mod.name}</span>
            `;
            modulesGrid.appendChild(label);
        });
    }

    const form = document.querySelector('#scanForm');
    const startBtn = document.querySelector('#startBtn');
    const progressArea = document.querySelector('#progressArea');
    const scanStatusText = document.querySelector('#scanStatusText');
    const progressBar = document.querySelector('#progressBar');
    const progressGlow = document.querySelector('#progressGlow');
    const terminalOutput = document.querySelector('#terminalOutput');
    const moduleCountText = document.querySelector('.module-count');
    let eventSource = null;

    // Time Estimate Logic
    const checkboxes = document.querySelectorAll('input[name="modules"]');
    checkboxes.forEach(cb => {
        cb.addEventListener('change', () => {
            updateSelectedCount();
            debounce(updateTimeEstimate, 300)();
        });
    });

    function updateSelectedCount() {
        const checkedModules = document.querySelectorAll('input[name="modules"]:checked');
        if (moduleCountText) moduleCountText.textContent = `${checkedModules.length} Selected`;
    }
    updateSelectedCount();

    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => { clearTimeout(timeout); func(...args); };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    async function updateTimeEstimate() {
        const checkedModules = Array.from(document.querySelectorAll('input[name="modules"]:checked')).map(cb => cb.value);

        const moduleMap = {
            "Port Scan": "port_scanner",
            "XSS": "xss_scanner",
            "Security Headers": "header_scanner",
            "Crawler": "crawler",
            "SQL Injection": "sql_injection",
            "SSL/TLS": "ssl_scanner",
            "DNS Recon": "dns_scanner",
            "Tech Fingerprinting": "tech_fingerprint",
            "Open Redirect": "open_redirect",
            "CSRF Detection": "csrf_scanner",
            "JavaScript Analysis": "js_analysis",
            "WAF Detection": "waf_detection",
            "CORS": "cors_scanner",
            "HTTP Methods": "http_methods_scanner",
            "Recon": "recon_scanner"
        };
        const mappedModules = checkedModules.map(m => moduleMap[m]).filter(Boolean);

        const estText = document.getElementById('timeEstimateText');
        if (estText) estText.innerHTML = '<i class="fas fa-spinner fa-spin text-gray-500 text-sm"></i>';

        try {
            const res = await fetch('/api/estimate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ modules: mappedModules })
            });
            const data = await res.json();

            if (estText) estText.textContent = data.display;

            const breakdown = data.phase_breakdown;
            const bdArea = document.getElementById('timeBreakdownArea');
            if (bdArea && breakdown) {
                bdArea.innerHTML = `
                    <li style="display:flex; justify-content:space-between"><span>Crawling:</span> <span style="color:var(--neon-green)">${breakdown.crawling}s</span></li>
                    <li style="display:flex; justify-content:space-between"><span>Parallel Scans:</span> <span style="color:var(--neon-green)">${breakdown.parallel_checks}s</span></li>
                    <li style="display:flex; justify-content:space-between"><span>Form Analysis:</span> <span style="color:var(--neon-green)">${breakdown.form_analysis}s</span></li>
                `;
            }
            const noteArea = document.getElementById('timeEstimateNote');
            if (noteArea && data.note) {
                noteArea.textContent = data.note;
            }
        } catch (e) {
            if (estText) estText.textContent = 'Unavailable';
        }
    }

    // Initial fetch on load
    updateTimeEstimate();

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const url = document.querySelector('#targetUrl').value;
        const terms = document.querySelector('#terms').checked;
        const checkedModules = Array.from(document.querySelectorAll('input[name="modules"]:checked')).map(cb => cb.value);
        const webhookUrl = document.querySelector('#webhookUrl') ? document.querySelector('#webhookUrl').value : null;
        const emailUrl = document.querySelector('#emailUrl') ? document.querySelector('#emailUrl').value : null;

        if (!terms) {
            alert('You must accept the authorization agreement.');
            return;
        }

        if (checkedModules.length === 0) {
            alert('Please select at least one scan module.');
            return;
        }

        // UI Reset
        startBtn.disabled = true;
        startBtn.querySelector('.btn-content').innerHTML = '<i class="fas fa-spinner fa-spin"></i> INITIALIZING...';
        form.style.opacity = '0.5';
        form.style.pointerEvents = 'none';

        progressArea.classList.remove('hidden');
        terminalOutput.innerHTML = '<div class="term-line timestamp" data-time="00:00:00">> Target selected. Awaiting modules initialization...</div>';
        progressBar.style.width = '5%';
        if (progressGlow) progressGlow.style.width = '5%';
        scanStatusText.textContent = 'Connecting to server...';

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    url: url,
                    modules: checkedModules,
                    webhook_url: webhookUrl,
                    email: emailUrl
                })
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Server error');
            }

            const data = await response.json();
            const scanId = data.scan_id;

            // Connect to SSE Stream
            connectStream(scanId, checkedModules.length);

        } catch (error) {
            addTerminalLine(`Error: ${error.message}`, 'error');
            startBtn.disabled = false;
            startBtn.querySelector('.btn-content').innerHTML = '<i class="fas fa-bolt"></i> INITIATE SCAN SEQUENCE';
            form.style.opacity = '1';
            form.style.pointerEvents = 'auto';
            scanStatusText.textContent = 'Failed to start.';
        }
    });

    function connectStream(scanId, moduleCount) {
        if (eventSource) eventSource.close();

        addTerminalLine('> Stream connected. Processing modules...');
        scanStatusText.textContent = 'Scan in progress...';

        // Rough progress calculation
        let progressStep = 90 / (moduleCount * 2 + 1); // rough events per module + scoring
        let currentProgress = 5;

        eventSource = new EventSource(`/api/scan/${scanId}/stream`);

        eventSource.onmessage = (event) => {
            const data = JSON.parse(event.data);

            if (data.status === 'completed' || data.message === 'Scan Complete.') {
                progressBar.style.width = '100%';
                if (progressGlow) progressGlow.style.width = '100%';
                scanStatusText.textContent = 'Scan Complete! Redirecting...';
                document.querySelector('.progress-percentage').textContent = '100%';
                addTerminalLine(`> ${data.message}`, 'success');

                eventSource.close();
                setTimeout(() => {
                    window.location.href = `/results/${scanId}`;
                }, 1500);
            }
            else if (data.status === 'error') {
                scanStatusText.textContent = 'Scan Error';
                progressBar.style.background = '#ef4444'; // critical color
                addTerminalLine(`> ERROR: ${data.message}`, 'error');
                eventSource.close();
                startBtn.disabled = false;
                form.style.opacity = '1';
                form.style.pointerEvents = 'auto';
            }
            else {
                addTerminalLine(`> ${data.message}`, data.status === 'warning' ? 'warning' : 'info');
                currentProgress = Math.min(98, currentProgress + progressStep);
                progressBar.style.width = `${currentProgress}%`;
                if (progressGlow) progressGlow.style.width = `${currentProgress}%`;
                document.querySelector('.progress-percentage').textContent = `${Math.floor(currentProgress)}%`;
            }
        };

        eventSource.onerror = () => {
            addTerminalLine('> Stream disconnected. Attempting to reconnect...', 'warning');
        };
    }

    const getTimestamp = () => {
        const now = new Date();
        return `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;
    };

    function addTerminalLine(text, typeClass = '') {
        const div = document.createElement('div');
        div.className = `term-line timestamp ${typeClass}`;
        div.setAttribute('data-time', getTimestamp());

        // rudimentary syntax coloring
        let formattedText = text;
        if (text.includes('complete') || text.includes('found')) {
            formattedText = text.replace(/complete|found/gi, match => `<span style="color:var(--neon-green)">${match}</span>`);
        }

        div.innerHTML = formattedText;
        terminalOutput.appendChild(div);

        // Auto-scroll
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
    }
});
