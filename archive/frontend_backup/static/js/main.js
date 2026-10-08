document.addEventListener('DOMContentLoaded', () => {
    const form = document.querySelector('#scanForm');
    const startBtn = document.querySelector('#startBtn');
    const progressArea = document.querySelector('#progressArea');
    const scanStatusText = document.querySelector('#scanStatusText');
    const progressBar = document.querySelector('#progressBar');
    const terminalOutput = document.querySelector('#terminalOutput');
    let eventSource = null;

    // Time Estimate Logic
    const checkboxes = document.querySelectorAll('input[name="modules"]');
    checkboxes.forEach(cb => {
        cb.addEventListener('change', debounce(updateTimeEstimate, 300));
    });

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
            "Tech Fingerprinting": "tech_fingerprint"
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
                    <div class="flex justify-between border-b border-gray-800 pb-1"><span>Crawling:</span> <span class="text-white">${breakdown.crawling}s</span></div>
                    <div class="flex justify-between border-b border-gray-800 py-1"><span>Parallel Scans:</span> <span class="text-white">${breakdown.parallel_checks}s</span></div>
                    <div class="flex justify-between pt-1"><span>Form Analysis:</span> <span class="text-white">${breakdown.form_analysis}s</span></div>
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
        startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> INITIALIZING...';
        startBtn.classList.add('opacity-50', 'cursor-not-allowed');

        progressArea.classList.remove('hidden');
        terminalOutput.innerHTML = '<div class="opacity-70">> Target selected. Awaiting modules initialization...</div>';
        progressBar.style.width = '5%';
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
            addTerminalLine(`Error: ${error.message}`, 'text-red-500');
            startBtn.disabled = false;
            startBtn.innerHTML = '<span class="relative z-10 flex items-center gap-2"><i class="fas fa-bolt"></i> START SCAN</span>';
            startBtn.classList.remove('opacity-50', 'cursor-not-allowed');
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
                scanStatusText.textContent = 'Scan Complete! Redirecting...';
                addTerminalLine(`> ${data.message}`, 'text-cyber font-bold');

                eventSource.close();
                setTimeout(() => {
                    window.location.href = `/results/${scanId}`;
                }, 1500);
            }
            else if (data.status === 'error') {
                scanStatusText.textContent = 'Scan Error';
                progressBar.classList.replace('bg-cyber', 'bg-red-500');
                addTerminalLine(`> ERROR: ${data.message}`, 'text-red-500');
                eventSource.close();
                startBtn.disabled = false;
            }
            else {
                addTerminalLine(`> ${data.message}`);
                currentProgress = Math.min(98, currentProgress + progressStep);
                progressBar.style.width = `${currentProgress}%`;
            }
        };

        eventSource.onerror = () => {
            // SSE auto-reconnects, but if we lost completely we can log it
            addTerminalLine('> Stream disconnected. Attempting to reconnect...', 'text-yellow-500');
        };
    }

    function addTerminalLine(text, colorClass = 'text-gray-300') {
        const div = document.createElement('div');
        div.className = `log-line py-1 border-b border-gray-800/50 ${colorClass}`;

        // rudimentary syntax coloring
        let formattedText = text;
        if (text.includes('complete') || text.includes('found')) {
            formattedText = text.replace(/complete|found/gi, match => `<span class="text-green-400">${match}</span>`);
        }

        div.innerHTML = formattedText;
        terminalOutput.appendChild(div);

        // Auto-scroll
        terminalOutput.parentElement.scrollTop = terminalOutput.parentElement.scrollHeight;
    }
});
