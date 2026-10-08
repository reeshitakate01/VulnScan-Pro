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
                <p class="text-white text-lg">Scan is ${data.status.toUpperCase()}</p>
                <a href="/" class="mt-4 text-cyber hover:underline">Return Home</a>
            `;
            return;
        }

        renderDashboard(data);

    } catch (error) {
        document.querySelector('#loadingState').innerHTML = `
            <p class="text-red-500 text-lg">Error loading results: ${error.message}</p>
        `;
    }
});

function renderDashboard(data) {
    document.querySelector('#loadingState').classList.add('hidden');
    document.querySelector('#dashboardContent').classList.remove('hidden');

    document.querySelector('#targetUrlText').textContent = data.url;
    document.querySelector('#scanStatusBadge').textContent = data.status;

    // Animation for score
    let targetScore = data.score || 0;
    animateValue("scoreValue", 0, targetScore, 1500);

    // Grade Colorization
    const gradeEl = document.querySelector('#scoreGrade');
    gradeEl.textContent = `Grade: ${data.grade || '-'}`;
    if (["A", "B"].includes(data.grade)) gradeEl.className = "mt-2 text-2xl font-bold text-cyber";
    else if (data.grade === "C") gradeEl.className = "mt-2 text-2xl font-bold text-medium";
    else if (data.grade === "D") gradeEl.className = "mt-2 text-2xl font-bold text-high";
    else gradeEl.className = "mt-2 text-2xl font-bold text-critical";

    document.querySelector('#summaryText').textContent = data.summary;

    const resultsJson = data.results_json;
    if (!resultsJson) return;

    // Findings count
    const findingCounts = resultsJson.score_data.findings_count;
    renderFindingsCounts(findingCounts);

    // Render Ring Chart
    renderChart(targetScore);

    // Render Modules logic
    const pdfDataModules = resultsJson.pdf_data.modules;
    renderModulesList(pdfDataModules);

    // OWASP logic
    const owaspSummary = resultsJson.pdf_data.owasp_summary;
    if (owaspSummary) {
        renderOwaspSummary(owaspSummary);
    }

    setupTabs();
}

function setupTabs() {
    const tabs = document.querySelectorAll('.tab-button');
    const contents = document.querySelectorAll('.tab-content');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => {
                t.classList.remove('border-cyber', 'text-cyber', 'active');
                t.classList.add('border-transparent', 'text-gray-500');
            });
            contents.forEach(c => c.classList.add('hidden'));

            tab.classList.remove('border-transparent', 'text-gray-500');
            tab.classList.add('border-cyber', 'text-cyber', 'active');

            const target = document.getElementById(tab.dataset.target);
            if (target) target.classList.remove('hidden');
        });
    });
}

function renderOwaspSummary(owaspData) {
    const container = document.getElementById('owaspContainer');
    container.innerHTML = "";

    const sevColors = {
        "CRITICAL": "bg-critical text-white",
        "HIGH": "bg-high text-white",
        "MEDIUM": "bg-medium text-black",
        "LOW": "bg-low text-black",
        "INFO": "bg-info text-black"
    };

    Object.entries(owaspData).forEach(([catId, data]) => {
        const hasFindings = data.count > 0;
        const opacityClass = hasFindings ? "opacity-100" : "opacity-40 grayscale";
        const badgeColor = hasFindings ? (sevColors[data.highest_severity] || sevColors.INFO) : "bg-gray-800 text-gray-500";

        const card = `
            <div class="bg-cardbg border ${hasFindings ? 'border-gray-700' : 'border-gray-800'} rounded-xl p-5 flex flex-col justify-between ${opacityClass} transition hover:opacity-100">
                <div>
                    <div class="flex justify-between items-start mb-2">
                        <span class="text-xs font-bold font-tech text-cyber ${hasFindings ? '' : 'text-gray-500'}">${catId}</span>
                        <span class="px-2 py-0.5 rounded text-xs font-bold ${badgeColor}">
                            ${hasFindings ? data.highest_severity : 'CLEAN'}
                        </span>
                    </div>
                    <h4 class="font-bold text-gray-200 text-sm mb-3">${data.name}</h4>
                </div>
                <div class="mt-auto">
                    <span class="text-3xl font-black font-tech ${hasFindings ? 'text-white' : 'text-gray-600'}">${data.count}</span>
                    <span class="text-xs text-gray-500 uppercase tracking-wide">findings</span>
                </div>
            </div>
        `;
        container.insertAdjacentHTML('beforeend', card);
    });
}

function renderFindingsCounts(counts) {
    const container = document.querySelector('#findingCountsArea');
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

    const colors = {
        "CRITICAL": "bg-critical text-white",
        "HIGH": "bg-high text-white",
        "MEDIUM": "bg-medium text-black",
        "LOW": "bg-low text-black",
        "INFO": "bg-info text-black"
    };

    container.innerHTML = order.map(sev => {
        const count = counts[sev] || 0;
        return `
            <div class="flex items-center justify-between">
                <div class="flex items-center gap-2">
                    <span class="w-3 h-3 rounded-full ${colors[sev].split(' ')[0]} shadow-[0_0_8px_currentColor] opacity-80"></span>
                    <span class="text-gray-300 font-medium">${sev}</span>
                </div>
                <span class="font-mono font-bold ${count > 0 ? (sev === 'CRITICAL' || sev === 'HIGH' ? 'text-red-400' : 'text-white') : 'text-gray-600'}">${count}</span>
            </div>
            `;
    }).join("");
}

function renderModulesList(modules) {
    const container = document.querySelector('#modulesContainer');
    container.innerHTML = "";

    if (Object.keys(modules).length === 0) {
        container.innerHTML = `< p class="text-gray-500 p-4 border border-gray-800 rounded-lg" > No findings in modules.</p > `;
        return;
    }

    const sevColors = {
        "CRITICAL": "bg-critical/20 text-critical border-critical/30",
        "HIGH": "bg-high/20 text-high border-high/30",
        "MEDIUM": "bg-medium/20 text-medium border-medium/30",
        "LOW": "bg-low/20 text-low border-low/30",
        "INFO": "bg-info/10 text-info border-info/20"
    };

    Object.entries(modules).forEach(([modName, findings]) => {
        if (!findings || findings.length === 0) return;

        const niceName = modName.replace(/_/g, " ").toUpperCase();

        const moduleHeader = `
            <div class="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden mb-4 group transition-shadow hover:shadow-lg hover:border-gray-700">
                <div class="px-6 py-4 bg-black/40 border-b border-gray-800 flex justify-between items-center cursor-pointer module-header">
                    <h4 class="font-bold text-lg font-tech tracking-wide text-gray-200">
                        <i class="fas fa-cube text-cyber bg-cyber/10 p-2 rounded mr-2"></i> ${niceName}
                    </h4>
                    <span class="bg-gray-800 text-gray-300 text-xs px-3 py-1 rounded-full font-bold">${findings.length} findings</span>
                </div>
                <div class="p-0 module-content hidden transform origin-top transition-all duration-300">
                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-sm text-gray-400">
                            <thead class="text-xs uppercase bg-black/60 text-gray-500">
                                <tr>
                                    <th class="px-6 py-3 font-semibold">Finding</th>
                                    <th class="px-6 py-3 font-semibold w-24">Severity</th>
                                    <th class="px-6 py-3 font-semibold">Description</th>
                                    <th class="px-6 py-3 font-semibold">Recommendation</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${findings.map(f => `
                                    <tr class="border-b border-gray-800/50 hover:bg-gray-800/20 transition-colors">
                                        <td class="px-6 py-4 font-medium text-gray-200">${f.Finding || '-'}</td>
                                        <td class="px-6 py-4">
                                            <span class="px-2.5 py-1 rounded text-xs font-bold border ${sevColors[f.Severity] || sevColors.INFO}">${f.Severity}</span>
                                        </td>
                                        <td class="px-6 py-4">${f.Description || '-'}</td>
                                        <td class="px-6 py-4 text-cyber">${f.Recommendation || '-'}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            `;

        container.insertAdjacentHTML('beforeend', moduleHeader);
    });

    // Accordion logic
    document.querySelectorAll('.module-header').forEach(header => {
        header.addEventListener('click', () => {
            const content = header.nextElementSibling;
            content.classList.toggle('hidden');
        });
    });

    // Auto-open first one
    const firstHeader = document.querySelector('.module-header');
    if (firstHeader) firstHeader.click();
}

function renderChart(score) {
    const ctx = document.getElementById('scoreChart').getContext('2d');

    let color = '#ef4444'; // Red for F/D
    if (score >= 90) color = '#00ff41'; // Cyber green
    else if (score >= 70) color = '#eab308'; // Yellow
    else if (score >= 60) color = '#f97316'; // Orange

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [score, 100 - score],
                backgroundColor: [color, '#262626'],
                borderWidth: 0,
                borderRadius: [5, 0]
            }]
        },
        options: {
            cutout: '80%',
            animation: { animateRotate: true, animateScale: true },
            plugins: { tooltip: { enabled: false }, legend: { display: false } },
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

function animateValue(id, start, end, duration) {
    if (start === end) {
        document.getElementById(id).innerHTML = end;
        return;
    }
    let range = end - start;
    let current = start;
    let increment = end > start ? 1 : -1;
    let stepTime = Math.abs(Math.floor(duration / range));
    let obj = document.getElementById(id);
    let timer = setInterval(function () {
        current += increment;
        obj.innerHTML = current;
        if (current == end) {
            clearInterval(timer);
        }
    }, stepTime);
}
