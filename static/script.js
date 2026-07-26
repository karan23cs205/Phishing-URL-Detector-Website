document.addEventListener('DOMContentLoaded', function() {
    
    // Only smooth scroll for internal page anchors starting with '#'
    document.querySelectorAll('nav.glass-navbar a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            if (targetId && document.querySelector(targetId)) {
                document.querySelector(targetId).scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
    
    const scanForm = document.getElementById('scan-form');
    let riskChart = null; // Reference to Chart.js instance

    scanForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        const urlInput = document.getElementById('url-input').value.trim();
        const globalLoader = document.getElementById('global-loader');
        const initialStateHero = document.getElementById('initial-state');
        const quickResult = document.getElementById('quick-result');
        const advancedThreatsSec = document.getElementById('advanced-threats');
        const featureBreakdownSec = document.getElementById('feature-breakdown');

        if (!urlInput) {
            alert("Please provide a target URL.");
            return;
        }

        // Show Loader & Hide Initial State
        globalLoader.classList.remove('hidden');
        if (initialStateHero) initialStateHero.classList.add('hidden');
        quickResult.classList.add('hidden');
        
        advancedThreatsSec.classList.add('hidden');
        featureBreakdownSec.classList.add('hidden');

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: urlInput })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || "Server error occurred.");
            }

            // Hide Loader & Display Data
            globalLoader.classList.add('hidden');
            populateDashboardResults(data);
            
            quickResult.classList.remove('hidden');
            advancedThreatsSec.classList.remove('hidden');
            featureBreakdownSec.classList.remove('hidden');

            advancedThreatsSec.classList.add('section-active');
            featureBreakdownSec.classList.add('section-active');

            // Scroll smoothly to results
            advancedThreatsSec.scrollIntoView({ behavior: 'smooth' });

        } catch (error) {
            globalLoader.classList.add('hidden');
            if (initialStateHero) initialStateHero.classList.remove('hidden');
            alert(`Scan Error: ${error.message}`);
            console.error("Scan Error:", error);
        }
    });

    function populateDashboardResults(data) {
        // Safe access defaults
        const indicators = data.indicators || {};
        const lexical = data.lexical_details || [0, 0, 0, 0, 0];
        const keywords = indicators.keyword_matches || [];

        // 1. Quick Status Header
        const badge = document.getElementById('threat-badge');
        badge.innerText = (data.risk_level || "UNKNOWN").toUpperCase();
        badge.className = `badge ${(data.status || 'safe').toLowerCase()}`;
        document.getElementById('quick-status').innerText = `${data.status || 'Unknown'} URL Detected`;

        // 2. Risk Metrics & Score Chart
        const score = data.risk_score !== undefined ? data.risk_score : 0;
        document.getElementById('risk-percent').innerText = `${score}%`;
        document.getElementById('risk-desc').innerText = (data.risk_level || "LOW").toUpperCase();

        if (typeof Chart !== 'undefined') {
            updateRiskChart(score, data.status || 'Safe');
        }

        // Signals List
        updateSignal('signal-trusted', indicators.trusted_domain);
        updateSignal('signal-https', indicators.https);
        updateSignal('signal-whois', indicators.domain_age_days);
        updateSignal('signal-lexical', lexical);

        // Critical Risks Callout
        populateCriticalList(indicators);

        // 3. Technical Feature Breakdown
        document.getElementById('feat-url-len').innerText = `${lexical[0] || 0} chars`;
        document.getElementById('feat-dots').innerText = lexical[2] || 0;
        document.getElementById('feat-hyphens').innerText = (lexical[3] || 0) > 0 ? "Yes" : "No";
        document.getElementById('feat-ip').innerText = lexical[4] ? "Yes" : "No";

        document.getElementById('feat-domain').innerText = data.domain || 'N/A';
        
        const ageValElement = document.getElementById('feat-age');
        const age = indicators.domain_age_days;
        if (indicators.trusted_domain) {
            ageValElement.innerText = "Verified Authority Domain";
            ageValElement.style.color = '#10b981';
        } else if (age === null || age === undefined || age === -1) {
            ageValElement.innerText = "Registry Lookup Unavailable";
            ageValElement.style.color = '#94a3b8';
        } else if (age < 365) {
            ageValElement.innerText = `${age} days (Young Domain)`;
            ageValElement.style.color = '#ef4444';
        } else {
            ageValElement.innerText = `${Math.round(age/365)} years (${age} days)`;
            ageValElement.style.color = '#10b981';
        }

        document.getElementById('feat-keywords').innerText = keywords.length > 0 ? `Detected (${keywords.join(', ')})` : "Clean";
        document.getElementById('feat-subdomain').innerText = indicators.deceptive_spoof ? "Yes" : "Clean";
        document.getElementById('analysis-summary').innerText = data.summary || "Scan completed.";
    }

    function updateRiskChart(score, status) {
        const ctx = document.getElementById('riskScoreChart');
        if (!ctx) return;

        let barColor = '#10b981';
        let bgColor = 'rgba(16, 185, 129, 0.1)';

        if (status === 'Suspicious') { barColor = '#f59e0b'; bgColor = 'rgba(245, 158, 11, 0.1)'; }
        else if (status === 'Phishing') { barColor = '#ef4444'; bgColor = 'rgba(239, 68, 68, 0.1)'; }

        if (riskChart) { riskChart.destroy(); }

        riskChart = new Chart(ctx.getContext('2d'), {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [score, 100 - score],
                    backgroundColor: [barColor, bgColor],
                    borderColor: [barColor, 'transparent'],
                    borderWidth: [2, 0],
                    cutout: '80%',
                    circumference: 250,
                    rotation: 235
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false }, tooltip: { enabled: false } },
                maintainAspectRatio: false
            }
        });
    }

    function updateSignal(id, condition) {
        const signal = document.getElementById(id);
        if (!signal) return;
        
        if (id === 'signal-https') {
            signal.innerText = condition ? "Yes (SSL Secured)" : "No (Insecure)";
            signal.className = condition ? "signal-status safe-status" : "signal-status crit-status";
        } else if (id === 'signal-trusted') {
            signal.innerText = condition ? "Yes (Whitelisted)" : "Not Listed";
            signal.className = condition ? "signal-status safe-status" : "signal-status warn-status";
        } else if (id === 'signal-whois') {
            if (condition !== null && condition !== undefined && condition !== -1) {
                signal.innerText = condition < 365 ? "Detected (Young)" : "Detected (Established)";
                signal.className = condition < 365 ? "signal-status crit-status" : "signal-status safe-status";
            } else {
                signal.innerText = "Registry Unavailable";
                signal.className = "signal-status warn-status";
            }
        } else if (id === 'signal-lexical') {
            const hasRisk = condition && (condition[4] || condition[1] || condition[2] > 4);
            signal.innerText = hasRisk ? "Risk Flags Found" : "Passed (Clean)";
            signal.className = hasRisk ? "signal-status crit-status" : "signal-status safe-status";
        }
    }

    function populateCriticalList(indicators) {
        const critListElement = document.getElementById('critical-list');
        if (!critListElement) return;
        critListElement.innerHTML = '';

        let detectedCrits = [];

        if (indicators.trusted_domain) {
             critListElement.innerHTML = '<p class="warn">None detected. Verified Whitelist Domain.</p>';
             return;
        }

        if (!indicators.https) detectedCrits.push("No HTTPS encryption detected.");
        if (indicators.domain_age_days < 365 && indicators.domain_age_days > 0) {
             detectedCrits.push(`Young domain age (${indicators.domain_age_days} days).`);
        }
        if (indicators.deceptive_spoof) detectedCrits.push("Brand spoofing keywords detected in subdomain.");

        const keywords = indicators.keyword_matches || [];
        if (keywords.length > 1) detectedCrits.push(`Threat keywords detected: ${keywords.join(', ')}.`);

        if (detectedCrits.length > 0) {
            critListElement.classList.remove('empty');
            const ul = document.createElement('ul');
            detectedCrits.forEach(crit => {
                const li = document.createElement('li');
                li.innerText = `⚠️ ${crit}`;
                ul.appendChild(li);
            });
            critListElement.appendChild(ul);
        } else {
            critListElement.classList.add('empty');
            critListElement.innerText = "None detected via heuristic analysis layers.";
        }
    }
});